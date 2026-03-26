import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import forge from "node-forge";
import { create } from "xmlbuilder2";
import PDFDocument from "pdfkit";
import QRCode from "qrcode";
import axios from "axios";
import https from "https";
import { XMLParser } from "fast-xml-parser";
import { SignedXml } from "xml-crypto";

dotenv.config();
const app = express();
app.use(cors());
app.use(express.json({ limit: "30mb" }));

app.use((err: any, _req: any, res: any, next: any) => {
  if (err instanceof SyntaxError && "body" in err) {
    console.error("JSON inválido recebido:", err.message);
    return res.status(400).json({
      autorizado: false,
      status: "ERROR",
      motivo: "JSON inválido",
      detalhe: err.message,
    });
  }
  next(err);
});

const PORT = Number(process.env.PORT || 3000);

const SEFAZ_GO = {
  autorizacaoProducao: "https://nfe.sefaz.go.gov.br/nfe/services/NFeAutorizacao4",
  autorizacaoHomologacao: "https://homolog.sefaz.go.gov.br/nfe/services/NFeAutorizacao4",
};

const CEP_PADRAO = "72856472";
const CIDADE_PADRAO = "LUZIANIA";
const UF_PADRAO = "GO";
const LOGRADOURO_PADRAO = "RUA MONCAO";
const NUMERO_PADRAO = "30";
const BAIRRO_PADRAO = "CENTRO";
const CODIGO_MUNICIPIO_PADRAO = "5212501";

function onlyNumbers(value: unknown): string {
  return String(value ?? "").replace(/\D/g, "");
}

function safeNumber(value: unknown, fallback = 0): number {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function pad(value: string | number, size: number): string {
  return String(value).padStart(size, "0");
}

function normalizarCep(value: unknown): string {
  const cep = onlyNumbers(value);
  return cep.length === 8 ? cep : CEP_PADRAO;
}

function normalizeText(value: unknown, fallback = ""): string {
  const text = String(value ?? fallback).trim()
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "") // Remove acentos (evita erro de schema)
    .toUpperCase();
  return text || fallback;
}

function calcularDVChave(chave43: string): string {
  let peso = 2;
  let soma = 0;
  for (let i = chave43.length - 1; i >= 0; i--) {
    soma += Number(chave43[i]) * peso;
    peso = peso === 9 ? 2 : peso + 1;
  }
  const mod = soma % 11;
  return mod === 0 || mod === 1 ? "0" : String(11 - mod);
}

async function obterCertificadoBuffer(payload: any): Promise<Buffer> {
  if (payload?.certificado?.pfx_base64) {
    return Buffer.from(String(payload.certificado.pfx_base64), "base64");
  }
  throw new Error("Certificado nao informado. Envie certificado.pfx_base64");
}

function extrairCertificadoEChave(buffer: Buffer, senha: string) {
  try {
    const p12Der = forge.util.createBuffer(buffer.toString("binary"));
    const p12Asn1 = forge.asn1.fromDer(p12Der);
    const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, senha);

    const certBags = p12.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag] || [];
    const keyBags = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag] || [];

    if (!certBags.length || !keyBags.length) throw new Error("Certificado ou chave nao encontrada.");

    const cert = certBags[0].cert;
    const key = keyBags[0].key;

    return {
      certPem: forge.pki.certificateToPem(cert),
      keyPem: forge.pki.privateKeyToPem(key),
      serialNumber: cert.serialNumber,
      validFrom: cert.validity.notBefore,
      validTo: cert.validity.notAfter,
    };
  } catch (error: any) {
    throw new Error(`Erro ao ler certificado A1: ${error.message}`);
  }
}

function gerarChave(payload: any, cNF: string, dhEmi: string): string {
  const cUF = "52";
  const aamm = dhEmi.substring(2, 4) + dhEmi.substring(5, 7); 
  const cnpj = onlyNumbers(payload.emitente?.cnpj);
  const mod = String(payload.modelo || 65);
  const serie = pad(payload.serie || 1, 3);
  const numero = pad(payload.numero || 1, 9);
  const tpEmis = "1";

  const base43 = `${cUF}${aamm}${cnpj.padStart(14, "0")}${mod}${serie}${numero}${tpEmis}${cNF}`;
  const dv = calcularDVChave(base43);
  return `${base43}${dv}`;
}

function gerarXmlBase(payload: any) {
  const tpAmb = String(payload.ambiente || 2);
  const dhEmiDate = payload?.data_emissao ? new Date(payload.data_emissao) : new Date();
  
  // Ajuste do fuso horario para -03:00 (Padrao Goias/Brasilia)
  const dhEmi = dhEmiDate.toLocaleString("sv-SE").replace(" ", "T") + "-03:00";
  
  const cNF = String(Math.floor(Math.random() * 99999999)).padStart(8, "0");
  const mod = String(payload.modelo || 65);
  const serie = String(payload.serie || 1);
  const numero = String(payload.numero || 1);
  const cnpj = onlyNumbers(payload.emitente?.cnpj);
  const cMun = String(payload.emitente?.codigo_municipio || CODIGO_MUNICIPIO_PADRAO);
  const chave = gerarChave(payload, cNF, dhEmi);
  const dv = chave.slice(-1);

  const root = create({ version: "1.0", encoding: "UTF-8" }).ele("NFe", { xmlns: "http://www.portalfiscal.inf.br/nfe" });
  const infNFe = root.ele("infNFe", { versao: "4.00", Id: `NFe${chave}` });

  const ide = infNFe.ele("ide");
  ide.ele("cUF").txt("52");
  ide.ele("cNF").txt(cNF);
  ide.ele("natOp").txt(normalizeText(payload.natureza_operacao, "VENDA"));
  ide.ele("mod").txt(mod);
  ide.ele("serie").txt(serie);
  ide.ele("nNF").txt(numero);
  ide.ele("dhEmi").txt(dhEmi);
  ide.ele("tpNF").txt("1");
  ide.ele("idDest").txt("1");
  ide.ele("cMunFG").txt(cMun);
  ide.ele("tpImp").txt("4");
  ide.ele("tpEmis").txt("1");
  ide.ele("cDV").txt(dv);
  ide.ele("tpAmb").txt(tpAmb);
  ide.ele("finNFe").txt("1");
  ide.ele("indFinal").txt("1");
  ide.ele("indPres").txt("1");
  ide.ele("procEmi").txt("0");
  ide.ele("verProc").txt("1.0.0");

  const emit = infNFe.ele("emit");
  emit.ele("CNPJ").txt(cnpj);
  emit.ele("xNome").txt(normalizeText(payload.emitente?.razao_social || payload.emitente?.nome_fantasia));
  
  const enderEmit = emit.ele("enderEmit");
  enderEmit.ele("xLgr").txt(normalizeText(payload.emitente?.logradouro, LOGRADOURO_PADRAO));
  enderEmit.ele("nro").txt(normalizeText(payload.emitente?.numero, NUMERO_PADRAO));
  enderEmit.ele("xBairro").txt(normalizeText(payload.emitente?.bairro, BAIRRO_PADRAO));
  enderEmit.ele("cMun").txt(cMun);
  enderEmit.ele("xMun").txt(normalizeText(payload.emitente?.cidade, CIDADE_PADRAO));
  enderEmit.ele("UF").txt(UF_PADRAO);
  enderEmit.ele("CEP").txt(normalizarCep(payload.emitente?.cep));
  enderEmit.ele("cPais").txt("1058");
  enderEmit.ele("xPais").txt("BRASIL");

  emit.ele("IE").txt(onlyNumbers(payload.emitente?.inscricao_estadual));
  emit.ele("CRT").txt(payload.emitente?.regime_tributario === "simples_nacional" ? "1" : "3");

  const cpfDest = onlyNumbers(payload?.destinatario?.cpf);
  if (cpfDest) {
    const dest = infNFe.ele("dest");
    dest.ele("CPF").txt(cpfDest);
    dest.ele("indIEDest").txt("9");
  }

  let totalProdutos = 0;
  payload.itens.forEach((item: any, idx: number) => {
    const quantidade = safeNumber(item.quantidade, 1);
    const valorUnitario = safeNumber(item.valor_unitario, 0);
    const valorTotal = quantidade * valorUnitario;
    totalProdutos += valorTotal;

    const det = infNFe.ele("det", { nItem: String(idx + 1) });
    const prod = det.ele("prod");
    prod.ele("cProd").txt(String(item.codigo_produto || idx + 1));
    prod.ele("cEAN").txt("SEM GTIN");
    prod.ele("xProd").txt(normalizeText(item.descricao, "ITEM"));
    prod.ele("NCM").txt(onlyNumbers(item.ncm) || "21069090");
    prod.ele("CFOP").txt(onlyNumbers(item.cfop) || "5102");
    prod.ele("uCom").txt(normalizeText(item.unidade, "UN"));
    prod.ele("qCom").txt(quantidade.toFixed(4));
    prod.ele("vUnCom").txt(valorUnitario.toFixed(2));
    prod.ele("vProd").txt(valorTotal.toFixed(2));
    prod.ele("cEANTrib").txt("SEM GTIN");
    prod.ele("uTrib").txt(normalizeText(item.unidade, "UN"));
    prod.ele("qTrib").txt(quantidade.toFixed(4));
    prod.ele("vUnTrib").txt(valorUnitario.toFixed(2));
    prod.ele("indTot").txt("1");

    const imposto = det.ele("imposto");
    const icms = imposto.ele("ICMS");
    const icmssn102 = icms.ele("ICMSSN102");
    icmssn102.ele("orig").txt("0");
    icmssn102.ele("CSOSN").txt("102");

    imposto.ele("PIS").ele("PISNT").ele("CST").txt("07");
    imposto.ele("COFINS").ele("COFINSNT").ele("CST").txt("07");
  });

  const total = infNFe.ele("total").ele("ICMSTot");
  [ "vBC", "vICMS", "vICMSDeson", "vFCP", "vBCST", "vST", "vFCPST", "vFCPSTRet" ].forEach(tag => total.ele(tag).txt("0.00"));
  total.ele("vProd").txt(totalProdutos.toFixed(2));
  total.ele("vFrete").txt("0.00");
  total.ele("vSeg").txt("0.00");
  total.ele("vDesc").txt("0.00");
  total.ele("vII").txt("0.00");
  total.ele("vIPI").txt("0.00");
  total.ele("vIPIDevol").txt("0.00");
  total.ele("vPIS").txt("0.00");
  total.ele("vCOFINS").txt("0.00");
  total.ele("vOutro").txt("0.00");
  total.ele("vNF").txt(totalProdutos.toFixed(2));
  total.ele("vTotTrib").txt("0.00");

  infNFe.ele("transp").ele("modFrete").txt("9");

  const pag = infNFe.ele("pag");
  const detPag = pag.ele("detPag");
  detPag.ele("tPag").txt(onlyNumbers(payload.pagamento?.forma_codigo) || "01");
  detPag.ele("vPag").txt(totalProdutos.toFixed(2));

  const infAdic = infNFe.ele("infAdic");
  infAdic.ele("infCpl").txt(tpAmb === "2" ? "EMITIDA EM AMBIENTE DE HOMOLOGACAO - SEM VALOR FISCAL" : "");

  return {
    xml: root.end({ headless: true, prettyPrint: false }),
    chave,
    valorFinal: totalProdutos,
  };
}

function assinarXmlNfce(xml: string, certPem: string, keyPem: string): string {
  const sig = new SignedXml();
  sig.privateKey = keyPem;
  sig.publicCert = certPem;
  sig.canonicalizationAlgorithm = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
  sig.signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
  sig.addReference({
    xpath: "//*[local-name(.)='infNFe']",
    transforms: ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"],
    digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
  });
  sig.computeSignature(xml, { location: { reference: "//*[local-name(.)='infNFe']", action: "after" } });
  return sig.getSignedXml();
}

function montarSoapAutorizacao(xmlAssinado: string): string {
  // CORRECAO: Extrai o XML da NFe garantindo que o namespace seja preservado dentro do lote
  const match = xmlAssinado.match(/<NFe[\s\S]*<\/NFe>/);
  if (!match) throw new Error("Erro ao extrair NFe para o SOAP");
  const nfeConteudo = match[0];

  return `<?xml version="1.0" encoding="utf-8"?>
<soap12:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap12="http://www.w3.org/2003/05/soap-envelope">
  <soap12:Body>
    <nfeDadosMsg xmlns="http://www.portalfiscal.inf.br/nfe/wsdl/NFeAutorizacao4">
      <enviNFe xmlns="http://www.portalfiscal.inf.br/nfe" versao="4.00">
        <idLote>1</idLote>
        <indSinc>1</indSinc>
        ${nfeConteudo}
      </enviNFe>
    </nfeDadosMsg>
  </soap12:Body>
</soap12:Envelope>`;
}

async function enviarParaSefazGo(xmlAssinado: string, ambiente: number, certBuffer: Buffer, senha: string): Promise<string> {
  const url = ambiente === 1 ? SEFAZ_GO.autorizacaoProducao : SEFAZ_GO.autorizacaoHomologacao;
  const soapBody = montarSoapAutorizacao(xmlAssinado);

  const httpsAgent = new https.Agent({ pfx: certBuffer, passphrase: senha, rejectUnauthorized: false, minVersion: "TLSv1.2" });
  
  const response = await axios.post(url, soapBody, {
    httpsAgent,
    headers: { "Content-Type": "application/soap+xml; charset=utf-8" },
    timeout: 30000,
    validateStatus: () => true,
  });

  return typeof response.data === "string" ? response.data : JSON.stringify(response.data);
}

function extrairAutorizacao(xmlRetorno: string) {
  const parser = new XMLParser({ ignoreAttributes: false });
  const parsed = parser.parse(xmlRetorno);
  const raw = JSON.stringify(parsed);

  return {
    cStat: raw.match(/"cStat":"?(\d+)"?/)?.[1] || "",
    xMotivo: raw.match(/"xMotivo":"([^"]+)"/)?.[1] || "",
    nProt: raw.match(/"nProt":"([^"]+)"/)?.[1] || "",
    chNFe: raw.match(/"chNFe":"([^"]+)"/)?.[1] || "",
  };
}

app.post("/nfce/emitir/:orderId", async (req, res) => {
  try {
    const payload = req.body;
    const certBuffer = await obterCertificadoBuffer(payload);
    const certInfo = extrairCertificadoEChave(certBuffer, String(payload.certificado.senha));
    
    const { xml, chave, valorFinal } = gerarXmlBase(payload);
    const xmlAssinado = assinarXmlNfce(xml, certInfo.certPem, certInfo.keyPem);
    
    const xmlRetorno = await enviarParaSefazGo(xmlAssinado, Number(payload.ambiente || 2), certBuffer, String(payload.certificado.senha));
    const retorno = extrairAutorizacao(xmlRetorno);

    if (retorno.cStat !== "100") {
      return res.status(400).json({ autorizado: false, status: "REJECTED", motivo: retorno.xMotivo, cStat: retorno.cStat });
    }

    return res.json({ autorizado: true, status: "AUTHORIZED", chave_acesso: retorno.chNFe || chave, protocolo: retorno.nProt });
  } catch (err: any) {
    console.error(err);
    return res.status(500).json({ autorizado: false, motivo: err.message });
  }
});

app.listen(PORT, () => console.log(`Rodando na porta ${PORT}`));