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
    console.error("❌ JSON inválido recebido:", err.message);
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
const LOGRADOURO_PADRAO = "RUA MONÇÃO";
const NUMERO_PADRAO = "30";
const BAIRRO_PADRAO = "CENTRO";
const CODIGO_MUNICIPIO_PADRAO = "5212501";
const CNAE_PADRAO = "5611203";

function onlyNumbers(value: unknown) {
  return String(value ?? "").replace(/\D/g, "");
}

function safeNumber(value: unknown, fallback = 0) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function pad(value: string | number, size: number) {
  return String(value).padStart(size, "0");
}

function normalizarCep(value: unknown) {
  const cep = onlyNumbers(value);
  return cep.length === 8 ? cep : CEP_PADRAO;
}

function calcularDVChave(chave43: string) {
  let peso = 2;
  let soma = 0;

  for (let i = chave43.length - 1; i >= 0; i--) {
    soma += Number(chave43[i]) * peso;
    peso = peso === 9 ? 2 : peso + 1;
  }

  const mod = soma % 11;
  return mod === 0 || mod === 1 ? "0" : String(11 - mod);
}

async function obterCertificadoBuffer(payload: any) {
  if (payload?.certificado?.pfx_base64) {
    console.log("Usando certificado via pfx_base64");
    return Buffer.from(String(payload.certificado.pfx_base64), "base64");
  }

  throw new Error("Certificado não informado. Envie certificado.pfx_base64");
}

function extrairCertificadoEChave(buffer: Buffer, senha: string) {
  try {
    const p12Der = forge.util.createBuffer(buffer.toString("binary"));
    const p12Asn1 = forge.asn1.fromDer(p12Der);
    const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, senha);

    const certBags =
      p12.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag] || [];

    const keyBags =
      p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[
        forge.pki.oids.pkcs8ShroudedKeyBag
      ] || [];

    if (!certBags.length) {
      throw new Error("Nenhum certificado encontrado no .p12/.pfx");
    }

    if (!keyBags.length) {
      throw new Error("Nenhuma chave privada encontrada no .p12/.pfx");
    }

    const cert = certBags[0].cert;
    const key = keyBags[0].key;

    return {
      cert,
      key,
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

function validarCertificadoP12(buffer: Buffer, senha: string) {
  const data = extrairCertificadoEChave(buffer, senha);
  return {
    serialNumber: data.serialNumber,
    validFrom: data.validFrom,
    validTo: data.validTo,
  };
}

function gerarChave(payload: any, cNF: string) {
  const cUF = "52";
  const aamm = new Date().toISOString().slice(2, 7).replace("-", "");
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
  const cUF = "52";
  const tpAmb = String(payload.ambiente || 2);
  const dhEmi = new Date().toISOString();
  const cNF = String(Math.floor(Math.random() * 99999999)).padStart(8, "0");
  const mod = String(payload.modelo || 65);
  const serie = String(payload.serie || 1);
  const numero = String(payload.numero || 1);
  const cnpj = onlyNumbers(payload.emitente?.cnpj);
  const cMun = String(payload.emitente?.codigo_municipio || CODIGO_MUNICIPIO_PADRAO);
  const chave = gerarChave(payload, cNF);
  const dv = chave.slice(-1);

  const cep = normalizarCep(payload.emitente?.cep);
  const ie = onlyNumbers(payload.emitente?.inscricao_estadual || "");
  const fone = onlyNumbers(payload.emitente?.fone || "");
  const logradouro = payload.emitente?.logradouro || LOGRADOURO_PADRAO;
  const numeroEndereco = payload.emitente?.numero || NUMERO_PADRAO;
  const bairro = payload.emitente?.bairro || BAIRRO_PADRAO;
  const cidade = payload.emitente?.cidade || CIDADE_PADRAO;
  const uf = payload.emitente?.uf || UF_PADRAO;
  const razaoSocial = payload.emitente?.razao_social || payload.emitente?.nome_fantasia || "";
  const naturezaOperacao = payload.natureza_operacao || "VENDA";
  const cnae = onlyNumbers(payload.emitente?.cnae || CNAE_PADRAO);

  console.log("CEP RECEBIDO:", payload.emitente?.cep);
  console.log("CEP NORMALIZADO:", cep);
  console.log("LOGRADOURO FINAL:", logradouro);
  console.log("BAIRRO FINAL:", bairro);
  console.log("CIDADE FINAL:", cidade);
  console.log("UF FINAL:", uf);

  if (!cnpj) throw new Error("emitente.cnpj é obrigatório");
  if (!ie) throw new Error("emitente.inscricao_estadual é obrigatória");
  if (!razaoSocial) throw new Error("emitente.razao_social é obrigatória");

  const root = create().ele("NFe", {
    xmlns: "http://www.portalfiscal.inf.br/nfe",
  });

  const infNFe = root.ele("infNFe", {
    versao: "4.00",
    Id: `NFe${chave}`,
  });

  const ide = infNFe.ele("ide");
  ide.ele("cUF").txt(cUF);
  ide.ele("cNF").txt(cNF);
  ide.ele("natOp").txt(naturezaOperacao);
  ide.ele("mod").txt(mod);
  ide.ele("serie").txt(serie);
  ide.ele("nNF").txt(numero);
  ide.ele("dhEmi").txt(dhEmi);
  ide.ele("dhSaiEnt").txt(dhEmi);
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
  ide.ele("indIntermed").txt("0");
  ide.ele("procEmi").txt("0");
  ide.ele("verProc").txt("1.0.0");

  const emit = infNFe.ele("emit");
  emit.ele("CNPJ").txt(cnpj);
  emit.ele("xNome").txt(razaoSocial);

  if (payload.emitente?.nome_fantasia) {
    emit.ele("xFant").txt(payload.emitente.nome_fantasia);
  }

  const enderEmit = emit.ele("enderEmit");
  enderEmit.ele("xLgr").txt(logradouro);
  enderEmit.ele("nro").txt(numeroEndereco);

  if (payload.emitente?.complemento) {
    enderEmit.ele("xCpl").txt(payload.emitente.complemento);
  }

  enderEmit.ele("xBairro").txt(bairro);
  enderEmit.ele("cMun").txt(cMun);
  enderEmit.ele("xMun").txt(cidade);
  enderEmit.ele("UF").txt(uf);
  enderEmit.ele("CEP").txt(cep);
  enderEmit.ele("cPais").txt("1058");
  enderEmit.ele("xPais").txt("BRASIL");

  if (fone) {
    enderEmit.ele("fone").txt(fone);
  }

  emit.ele("IE").txt(ie);
  emit.ele("CNAE").txt(cnae);
  emit.ele("CRT").txt(payload.emitente?.regime_tributario === "simples_nacional" ? "1" : "3");

  if (payload.destinatario?.cpf) {
    const dest = infNFe.ele("dest");
    dest.ele("CPF").txt(onlyNumbers(payload.destinatario.cpf));
    if (payload.destinatario?.nome) {
      dest.ele("xNome").txt(payload.destinatario.nome);
    }
    dest.ele("indIEDest").txt("9");
  }

  let totalProdutos = 0;

  for (const item of payload.itens || []) {
    const quantidade = safeNumber(item.quantidade, 1);
    const valorUnitario = safeNumber(item.valor_unitario, 0);
    const valorTotal =
      item.valor_total != null
        ? safeNumber(item.valor_total, valorUnitario * quantidade)
        : valorUnitario * quantidade;

    totalProdutos += valorTotal;

    const det = infNFe.ele("det", { nItem: String(item.numero_item || 1) });
    const prod = det.ele("prod");

    prod.ele("cProd").txt(String(item.codigo_produto || item.numero_item || "1"));
    prod.ele("cEAN").txt("SEM GTIN");
    prod.ele("xProd").txt(item.descricao || "ITEM");
    prod.ele("NCM").txt(item.ncm || "21069090");
    prod.ele("CFOP").txt(item.cfop || "5102");
    prod.ele("uCom").txt(item.unidade || "UN");
    prod.ele("qCom").txt(quantidade.toFixed(4));
    prod.ele("vUnCom").txt(valorUnitario.toFixed(2));
    prod.ele("vProd").txt(valorTotal.toFixed(2));
    prod.ele("cEANTrib").txt("SEM GTIN");
    prod.ele("uTrib").txt(item.unidade || "UN");
    prod.ele("qTrib").txt(quantidade.toFixed(4));
    prod.ele("vUnTrib").txt(valorUnitario.toFixed(2));
    prod.ele("indTot").txt("1");

    const imposto = det.ele("imposto");
    imposto.ele("vTotTrib").txt("0.00");

    const icms = imposto.ele("ICMS");
    const icmssn102 = icms.ele("ICMSSN102");
    icmssn102.ele("orig").txt(String(item?.impostos?.icms?.origem ?? "0"));
    icmssn102.ele("CSOSN").txt(String(item?.impostos?.icms?.csosn ?? "102"));
    icmssn102.ele("pCredSN").txt("0.00");
    icmssn102.ele("vCredICMSSN").txt("0.00");

    const pis = imposto.ele("PIS");
    const pisnt = pis.ele("PISNT");
    pisnt.ele("CST").txt(String(item?.impostos?.pis?.cst ?? "07"));

    const cofins = imposto.ele("COFINS");
    const cofinsnt = cofins.ele("COFINSNT");
    cofinsnt.ele("CST").txt(String(item?.impostos?.cofins?.cst ?? "07"));
  }

  const valorNF = safeNumber(payload.totais?.valor_total, totalProdutos);

  const total = infNFe.ele("total").ele("ICMSTot");
  total.ele("vBC").txt("0.00");
  total.ele("vICMS").txt("0.00");
  total.ele("vICMSDeson").txt("0.00");
  total.ele("vFCP").txt("0.00");
  total.ele("vBCST").txt("0.00");
  total.ele("vST").txt("0.00");
  total.ele("vFCPST").txt("0.00");
  total.ele("vFCPSTRet").txt("0.00");
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
  total.ele("vNF").txt(valorNF.toFixed(2));
  total.ele("vTotTrib").txt("0.00");

  const transp = infNFe.ele("transp");
  transp.ele("modFrete").txt("9");

  const pag = infNFe.ele("pag");
  const detPag = pag.ele("detPag");
  detPag.ele("tPag").txt(String(payload.pagamento?.forma_codigo || "01"));
  detPag.ele("vPag").txt(safeNumber(payload.pagamento?.valor, valorNF).toFixed(2));

  const troco = safeNumber(payload.pagamento?.troco, 0);
  if (troco > 0) {
    pag.ele("vTroco").txt(troco.toFixed(2));
  }

  const infAdic = infNFe.ele("infAdic");
  const infCpl =
    tpAmb === "2"
      ? "EMITIDA EM AMBIENTE DE HOMOLOGACAO - SEM VALOR FISCAL"
      : payload.informacoes_complementares || "";
  infAdic.ele("infCpl").txt(infCpl);

  return {
    xml: root.end({ headless: true, prettyPrint: false }),
    chave,
  };
}

function assinarXmlNfce(xml: string, certPem: string, keyPem: string) {
  const xmlLimpo = xml.replace(/<\?xml[^>]*\?>/i, "").trim();

  const sig = new SignedXml();
  sig.privateKey = keyPem;
  sig.publicCert = certPem;
  sig.canonicalizationAlgorithm = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
  sig.signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

  sig.addReference({
    xpath: "//*[local-name(.)='infNFe']",
    transforms: [
      "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
      "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
    ],
    digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
  });

  sig.computeSignature(xmlLimpo, {
    location: {
      reference: "//*[local-name(.)='infNFe']",
      action: "after",
    },
  });

  return sig.getSignedXml();
}

function extrairApenasNFe(xmlAssinado: string) {
  const xmlSemDeclaracao = xmlAssinado.replace(/<\?xml[^>]*\?>/i, "").trim();
  const inicio = xmlSemDeclaracao.indexOf("<NFe");
  const fim = xmlSemDeclaracao.lastIndexOf("</NFe>");

  if (inicio === -1 || fim === -1) {
    console.error("XML ASSINADO COMPLETO:");
    console.log(xmlAssinado);
    throw new Error("Não encontrou <NFe> no XML assinado");
  }

  return xmlSemDeclaracao.substring(inicio, fim + 6);
}

function montarSoapAutorizacao(xmlAssinado: string) {
  const nfeXml = extrairApenasNFe(xmlAssinado);

  console.log("========== NFE EXTRAIDO ==========");
  console.log(nfeXml);
  console.log("========== FIM NFE EXTRAIDO ==========");

  return `<?xml version="1.0" encoding="utf-8"?>
<soap12:Envelope xmlns:soap12="http://www.w3.org/2003/05/soap-envelope">
  <soap12:Body>
    <nfeDadosMsg xmlns="http://www.portalfiscal.inf.br/nfe/wsdl/NFeAutorizacao4">
      <enviNFe xmlns="http://www.portalfiscal.inf.br/nfe" versao="4.00">
        <idLote>1</idLote>
        <indSinc>1</indSinc>
        ${nfeXml}
      </enviNFe>
    </nfeDadosMsg>
  </soap12:Body>
</soap12:Envelope>`;
}

async function enviarParaSefazGo(
  xmlAssinado: string,
  ambiente: number,
  certBuffer: Buffer,
  senha: string
) {
  const url =
    ambiente === 1
      ? SEFAZ_GO.autorizacaoProducao
      : SEFAZ_GO.autorizacaoHomologacao;

  const soapBody = montarSoapAutorizacao(xmlAssinado);

  console.log("========== XML ENVIADO SEFAZ ==========");
  console.log(soapBody);
  console.log("========== FIM XML ENVIADO ==========");

  const httpsAgent = new https.Agent({
    pfx: certBuffer,
    passphrase: senha,
    rejectUnauthorized: false,
    minVersion: "TLSv1.2",
    keepAlive: false,
  });

  const response = await axios.post(url, soapBody, {
    httpsAgent,
    headers: {
      "Content-Type": "application/soap+xml; charset=utf-8",
      Accept: "application/soap+xml, text/plain, */*",
    },
    timeout: 30000,
    maxBodyLength: Infinity,
    maxContentLength: Infinity,
    validateStatus: () => true,
  });

  console.log("========== STATUS HTTP SEFAZ ==========");
  console.log(response.status);
  console.log("========== RESPOSTA SEFAZ BRUTA ==========");
  console.log(response.data);
  console.log("========== FIM RESPOSTA SEFAZ ==========");

  if (response.status >= 400) {
    throw new Error(
      `SEFAZ retornou HTTP ${response.status}: ${
        typeof response.data === "string" ? response.data : JSON.stringify(response.data)
      }`
    );
  }

  return typeof response.data === "string" ? response.data : JSON.stringify(response.data);
}

function extrairAutorizacao(xmlRetorno: string) {
  const parser = new XMLParser({
    ignoreAttributes: false,
    attributeNamePrefix: "@_",
  });

  const parsed = parser.parse(xmlRetorno);
  const raw = JSON.stringify(parsed);

  const cStatMatch = raw.match(/"cStat":"?(\d+)"?/);
  const xMotivoMatch = raw.match(/"xMotivo":"([^"]+)"/);
  const nProtMatch = raw.match(/"nProt":"([^"]+)"/);
  const chNFeMatch = raw.match(/"chNFe":"([^"]+)"/);

  const cStat = cStatMatch?.[1] || "";
  const xMotivo = xMotivoMatch?.[1] || "";
  const nProt = nProtMatch?.[1] || "";
  const chNFe = chNFeMatch?.[1] || "";

  const resumo = {
    cStat,
    xMotivo,
    nProt,
    chNFe,
    rawXml: xmlRetorno,
  };

  console.log("========== RESUMO SEFAZ ==========");
  console.log(resumo);
  console.log("========== FIM RESUMO ==========");

  return resumo;
}

async function gerarDanfeBase64(payload: any, numero: number, chaveAcesso: string) {
  const doc = new PDFDocument({ margin: 20, size: "A4" });
  const buffers: Buffer[] = [];

  doc.on("data", (chunk) => buffers.push(chunk));
  const done = new Promise<Buffer>((resolve) => {
    doc.on("end", () => resolve(Buffer.concat(buffers)));
  });

  doc.fontSize(16).text("DANFE NFC-e", { align: "center" });
  doc.moveDown();
  doc.fontSize(10).text(`Emitente: ${payload.emitente?.razao_social || ""}`);
  doc.text(`CNPJ: ${payload.emitente?.cnpj || ""}`);
  doc.text(`Número: ${numero}  Série: ${payload.serie || 1}`);
  doc.text(`Chave: ${chaveAcesso}`);
  doc.text(`Ambiente: ${payload.ambiente === 2 ? "HOMOLOGACAO" : "PRODUCAO"}`);
  doc.moveDown();

  doc.text("Itens:");
  for (const item of payload.itens || []) {
    doc.text(
      `${item.numero_item}. ${item.descricao} | Qtd: ${safeNumber(item.quantidade, 1)} | Unit: ${safeNumber(
        item.valor_unitario,
        0
      ).toFixed(2)} | Total: ${safeNumber(item.valor_total, 0).toFixed(2)}`
    );
  }

  doc.moveDown();
  doc.text(`Valor total: ${safeNumber(payload.totais?.valor_total, 0).toFixed(2)}`);

  const qrData = `CHAVE=${chaveAcesso}`;
  const qrDataUrl = await QRCode.toDataURL(qrData);
  const qrBase64 = qrDataUrl.replace(/^data:image\/png;base64,/, "");
  const qrBuffer = Buffer.from(qrBase64, "base64");

  doc.moveDown();
  doc.text("QR Code:");
  doc.image(qrBuffer, { fit: [120, 120] });

  doc.end();

  const pdfBuffer = await done;
  return pdfBuffer.toString("base64");
}

app.get("/", (_req, res) => {
  res.send("Servidor fiscal rodando 🚀");
});

app.get("/health", (_req, res) => {
  res.json({ ok: true, service: "nfce-backend" });
});

app.post("/nfce/emitir/:orderId", async (req, res) => {
  try {
    console.log("📦 ORDER ID:", req.params.orderId);
    console.log("📦 PAYLOAD RECEBIDO:");
    console.log(JSON.stringify(req.body, null, 2));

    const orderId = req.params.orderId;
    const payload = req.body;

    if (!orderId) {
      return res.status(400).json({
        autorizado: false,
        status: "ERROR",
        motivo: "orderId não informado",
      });
    }

    const camposFaltando: string[] = [];

    if (!payload?.emitente?.cnpj) camposFaltando.push("emitente.cnpj");
    if (!payload?.emitente?.razao_social && !payload?.emitente?.nome_fantasia) {
      camposFaltando.push("emitente.razao_social");
    }
    if (!payload?.emitente?.inscricao_estadual) camposFaltando.push("emitente.inscricao_estadual");
    if (!payload?.certificado?.senha) camposFaltando.push("certificado.senha");
    if (!payload?.certificado?.pfx_base64) camposFaltando.push("certificado.pfx_base64");
    if (!Array.isArray(payload?.itens) || payload.itens.length === 0) camposFaltando.push("itens");
    if (payload?.totais?.valor_total == null) camposFaltando.push("totais.valor_total");
    if (!payload?.pagamento?.forma_codigo) camposFaltando.push("pagamento.forma_codigo");
    if (payload?.pagamento?.valor == null) camposFaltando.push("pagamento.valor");

    if (camposFaltando.length > 0) {
      console.log("❌ CAMPOS FALTANDO:", camposFaltando);
      return res.status(400).json({
        autorizado: false,
        status: "ERROR",
        motivo: "Payload fiscal incompleto",
        campos_faltando: camposFaltando,
      });
    }

    const certBuffer = await obterCertificadoBuffer(payload);
    const certInfo = extrairCertificadoEChave(certBuffer, String(payload.certificado.senha));
    validarCertificadoP12(certBuffer, String(payload.certificado.senha));

    const { xml, chave } = gerarXmlBase(payload);
    const xmlAssinado = assinarXmlNfce(xml, certInfo.certPem, certInfo.keyPem);

    const xmlRetorno = await enviarParaSefazGo(
      xmlAssinado,
      Number(payload.ambiente || 2),
      certBuffer,
      String(payload.certificado.senha)
    );

    const retorno = extrairAutorizacao(xmlRetorno);

    if (retorno.cStat !== "100") {
      return res.status(400).json({
        autorizado: false,
        status: "REJECTED",
        motivo: retorno.xMotivo || `SEFAZ retornou cStat ${retorno.cStat}`,