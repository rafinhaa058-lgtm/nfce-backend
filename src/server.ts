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

const PORT = Number(process.env.PORT || 3000);

const SEFAZ_GO = {
  autorizacaoProducao: "https://nfe.sefaz.go.gov.br/nfe/services/NFeAutorizacao4",
  autorizacaoHomologacao: "https://homolog.sefaz.go.gov.br/nfe/services/NFeAutorizacao4",
};

function onlyNumbers(value: unknown) {
  return String(value || "").replace(/\D/g, "");
}

function safeNumber(value: unknown, fallback = 0) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

async function obterCertificadoBuffer(payload: any) {
  if (payload?.certificado?.pfx_base64) {
    console.log("Usando certificado via pfx_base64");
    return Buffer.from(payload.certificado.pfx_base64, "base64");
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
  const serie = String(payload.serie || 1);
  const numero = String(payload.numero || 1);
  const tpEmis = "1";

  const base = `${cUF}${aamm}${cnpj.padStart(14, "0")}${mod}${serie.padStart(3, "0")}${numero.padStart(9, "0")}${tpEmis}${cNF}`;
  const dv = calcularDVChave(base);

  return `${base}${dv}`;
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

function gerarXmlBase(payload: any) {
  const cUF = "52";
  const tpAmb = String(payload.ambiente || 2);
  const dhEmi = new Date().toISOString();
  const cNF = String(Math.floor(Math.random() * 99999999)).padStart(8, "0");
  const mod = String(payload.modelo || 65);
  const serie = String(payload.serie || 1);
  const numero = String(payload.numero || 1);
  const cnpj = onlyNumbers(payload.emitente?.cnpj);
  const cMun = String(payload.emitente?.codigo_municipio || "5212501");
  const chave = gerarChave(payload, cNF);
  const dv = chave.slice(-1);

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
  ide.ele("natOp").txt(payload.natureza_operacao || "VENDA");
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
  emit.ele("xNome").txt(payload.emitente?.razao_social || "");
  emit.ele("xFant").txt(payload.emitente?.nome_fantasia || payload.emitente?.razao_social || "");

  const enderEmit = emit.ele("enderEmit");
  enderEmit.ele("xLgr").txt(payload.emitente?.logradouro || "NAO INFORMADO");
  enderEmit.ele("nro").txt(payload.emitente?.numero || "SN");
  enderEmit.ele("xBairro").txt(payload.emitente?.bairro || "CENTRO");
  enderEmit.ele("cMun").txt(cMun);
  enderEmit.ele("xMun").txt(payload.emitente?.cidade || "LUZIANIA");
  enderEmit.ele("UF").txt(payload.emitente?.uf || "GO");
  enderEmit.ele("CEP").txt(onlyNumbers(payload.emitente?.cep || ""));
  enderEmit.ele("cPais").txt("1058");
  enderEmit.ele("xPais").txt("BRASIL");
  enderEmit.ele("fone").txt(onlyNumbers(payload.emitente?.fone || ""));

  emit.ele("IE").txt(onlyNumbers(payload.emitente?.inscricao_estadual));
  emit.ele("CRT").txt(payload.emitente?.regime_tributario === "simples_nacional" ? "1" : "3");

  if (payload.destinatario?.cpf) {
    const dest = infNFe.ele("dest");
    dest.ele("CPF").txt(onlyNumbers(payload.destinatario.cpf));
    if (payload.destinatario.nome) {
      dest.ele("xNome").txt(payload.destinatario.nome);
    }
    dest.ele("indIEDest").txt("9");
  }

  let totalProdutos = 0;

  for (const item of payload.itens || []) {
    totalProdutos += safeNumber(item.valor_total);

    const det = infNFe.ele("det", { nItem: String(item.numero_item) });
    const prod = det.ele("prod");

    prod.ele("cProd").txt(String(item.codigo_produto || item.numero_item));
    prod.ele("cEAN").txt("SEM GTIN");
    prod.ele("xProd").txt(item.descricao || "ITEM");
    prod.ele("NCM").txt(item.ncm || "21069090");
    prod.ele("CFOP").txt(item.cfop || "5102");
    prod.ele("uCom").txt(item.unidade || "UN");
    prod.ele("qCom").txt(safeNumber(item.quantidade, 1).toFixed(4));
    prod.ele("vUnCom").txt(safeNumber(item.valor_unitario).toFixed(2));
    prod.ele("vProd").txt(safeNumber(item.valor_total).toFixed(2));
    prod.ele("cEANTrib").txt("SEM GTIN");
    prod.ele("uTrib").txt(item.unidade || "UN");
    prod.ele("qTrib").txt(safeNumber(item.quantidade, 1).toFixed(4));
    prod.ele("vUnTrib").txt(safeNumber(item.valor_unitario).toFixed(2));
    prod.ele("indTot").txt("1");

    const imposto = det.ele("imposto");
    imposto.ele("vTotTrib").txt("0.00");

    const icms = imposto.ele("ICMS");
    const icmssn102 = icms.ele("ICMSSN102");
    icmssn102.ele("orig").txt("0");
    icmssn102.ele("CSOSN").txt("102");

    const pis = imposto.ele("PIS");
    const pisnt = pis.ele("PISNT");
    pisnt.ele("CST").txt("07");

    const cofins = imposto.ele("COFINS");
    const cofinsnt = cofins.ele("COFINSNT");
    cofinsnt.ele("CST").txt("07");
  }

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
  total.ele("vNF").txt(safeNumber(payload.totais?.valor_total, totalProdutos).toFixed(2));
  total.ele("vTotTrib").txt("0.00");

  const transp = infNFe.ele("transp");
  transp.ele("modFrete").txt("9");

  const pag = infNFe.ele("pag");
  const detPag = pag.ele("detPag");
  detPag.ele("tPag").txt(payload.pagamento?.forma_codigo || "01");
  detPag.ele("vPag").txt(safeNumber(payload.pagamento?.valor, totalProdutos).toFixed(2));

  const infAdic = infNFe.ele("infAdic");
  infAdic.ele("infCpl").txt(
    tpAmb === "2"
      ? "EMITIDA EM AMBIENTE DE HOMOLOGACAO - SEM VALOR FISCAL"
      : (payload.informacoes_complementares || "")
  );

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
      `${item.numero_item}. ${item.descricao} | Qtd: ${item.quantidade} | Unit: ${safeNumber(
        item.valor_unitario
      ).toFixed(2)} | Total: ${safeNumber(item.valor_total).toFixed(2)}`
    );
  }

  doc.moveDown();
  doc.text(`Valor total: ${safeNumber(payload.totais?.valor_total).toFixed(2)}`);

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
    const orderId = req.params.orderId;
    const payload = req.body;

    if (!orderId) {
      return res.status(400).json({
        autorizado: false,
        status: "ERROR",
        motivo: "orderId não informado",
      });
    }

    if (!payload?.emitente?.cnpj || !payload?.certificado?.senha) {
      return res.status(400).json({
        autorizado: false,
        status: "ERROR",
        motivo: "Payload fiscal incompleto",
      });
    }

    const certBuffer = await obterCertificadoBuffer(payload);
    const certInfo = extrairCertificadoEChave(certBuffer, payload.certificado.senha);
    validarCertificadoP12(certBuffer, payload.certificado.senha);

    const { xml, chave } = gerarXmlBase(payload);
    const xmlAssinado = assinarXmlNfce(xml, certInfo.certPem, certInfo.keyPem);

    const xmlRetorno = await enviarParaSefazGo(
      xmlAssinado,
      Number(payload.ambiente || 2),
      certBuffer,
      payload.certificado.senha
    );

    const retorno = extrairAutorizacao(xmlRetorno);

    if (retorno.cStat !== "100") {
      return res.status(400).json({
        autorizado: false,
        status: "REJECTED",
        motivo: retorno.xMotivo || `SEFAZ retornou cStat ${retorno.cStat}`,
        cStat: retorno.cStat,
        resposta_xml: xmlRetorno,
        sefaz_debug: retorno,
      });
    }

    const numero = Number(payload.numero || 1);
    const serie = Number(payload.serie || 1);
    const chaveAcesso = retorno.chNFe || chave;
    const danfeBase64 = await gerarDanfeBase64(payload, numero, chaveAcesso);

    return res.json({
      autorizado: true,
      status: "AUTHORIZED",
      numero,
      serie,
      chave_acesso: chaveAcesso,
      protocolo: retorno.nProt,
      xml_autorizado_base64: Buffer.from(xmlRetorno, "utf-8").toString("base64"),
      danfe_base64: danfeBase64,
      sefaz_debug: {
        cStat: retorno.cStat,
        xMotivo: retorno.xMotivo,
        nProt: retorno.nProt,
        chNFe: retorno.chNFe,
      },
    });
  } catch (err: any) {
    console.error("Erro no backend fiscal:", err);
    return res.status(500).json({
      autorizado: false,
      status: "ERROR",
      motivo: err.message || "Erro interno no backend fiscal",
    });
  }
});

app.listen(PORT, () => {
  console.log(`🚀 Backend fiscal externo rodando em http://localhost:${PORT}`);
});