// VERSÃO REVISADA PARA BUILD RAILWAY - 14/04/2026 16:40
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import forge from "node-forge";
import { create } from "xmlbuilder2";
import QRCode from "qrcode";
import axios from "axios";
import https from "https";
import crypto from "crypto";
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

// --- AUXILIARES ---
function onlyNumbers(value: any): string {
  return String(value ?? "").replace(/\D/g, "");
}

function safeNumber(value: any, fallback = 0): number {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function normalizeText(value: any, fallback = ""): string {
  let text = String(value ?? fallback).trim();
  text = text.normalize("NFD").replace(/[\u0300-\u036f]/g, "");
  return text.replace(/[<&"'>]/g, "").toUpperCase() || fallback;
}

function pad(value: any, size: number): string {
  return String(value).padStart(size, "0");
}

function formatarDataSefaz(data?: any): string {
  const local = data ? new Date(data) : new Date();
  const offset = -3; 
  const d = new Date(local.getTime() + (offset * 60 * 60 * 1000));
  return d.toISOString().replace(/\.\d+Z$/, "-03:00");
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

function gerarQrCodeNfce(chave: string, ambiente: number, cscId: string, csc: string): string {
  const urlBase = ambiente === 1 
    ? "https://nfe.sefaz.go.gov.br/nfeweb/sites/nfce/danfeNFCe"
    : "https://homolog.sefaz.go.gov.br/nfeweb/sites/nfce/danfeNFCe";
  const cIdToken = pad(onlyNumbers(cscId), 6);
  const concat = `${chave}|2|${ambiente}|${cIdToken}${csc}`;
  const hash = crypto.createHash("sha1").update(concat).digest("hex").toUpperCase();
  return `${urlBase}?p=${chave}|2|${ambiente}|${cIdToken}|${hash}`;
}

// --- EMISSÃO ---
app.post("/nfce/emitir/:orderId", async (req, res) => {
  try {
    const payload = req.body;
    const tpAmb = Number(payload.ambiente || 2);
    
    if (!payload.certificado?.pfx_base64) throw new Error("PFX ausente.");
    const certBuffer = Buffer.from(payload.certificado.pfx_base64, "base64");
    const p12 = forge.pkcs12.pkcs12FromAsn1(forge.asn1.fromDer(forge.util.createBuffer(certBuffer.toString("binary"))), String(payload.certificado.senha));
    
    const certBag = p12.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag]![0];
    const keyBag = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag]![0];
    
    const certPem = forge.pki.certificateToPem(certBag.cert!);
    const keyPem = forge.pki.privateKeyToPem(keyBag.key!);

    const cnpj = onlyNumbers(payload.emitente.cnpj);
    const dhEmi = formatarDataSefaz(payload.data_emissao);
    const cNF = pad(Math.floor(Math.random() * 99999999), 8);
    const base43 = `52${dhEmi.slice(2, 4)}${dhEmi.slice(5, 7)}${cnpj.padStart(14, "0")}65${pad(payload.serie || 1, 3)}${pad(payload.numero || 1, 9)}1${cNF}`;
    const chave = `${base43}${calcularDVChave(base43)}`;

    const xmlObj = create({ version: "1.0", encoding: "UTF-8" }).ele("NFe", { xmlns: "http://www.portalfiscal.inf.br/nfe" });
    const infNFe = xmlObj.ele("infNFe", { versao: "4.00", Id: `NFe${chave}` });

    const ide = infNFe.ele("ide");
    ide.ele("cUF").txt("52").up()
       .ele("cNF").txt(cNF).up()
       .ele("natOp").txt(normalizeText(payload.natureza_operacao, "VENDA")).up()
       .ele("mod").txt("65").up()
       .ele("serie").txt(String(payload.serie || 1)).up()
       .ele("nNF").txt(String(payload.numero || 1)).up()
       .ele("dhEmi").txt(dhEmi).up()
       .ele("tpNF").txt("1").up()
       .ele("idDest").txt("1").up()
       .ele("cMunFG").txt("5212501").up()
       .ele("tpImp").txt("4").up()
       .ele("tpEmis").txt("1").up()
       .ele("cDV").txt(chave.slice(-1)).up()
       .ele("tpAmb").txt(String(tpAmb)).up()
       .ele("finNFe").txt("1").up()
       .ele("indFinal").txt("1").up()
       .ele("indPres").txt("1").up()
       .ele("procEmi").txt("0").up()
       .ele("verProc").txt("1.0.0").up();

    const emit = infNFe.ele("emit");
    emit.ele("CNPJ").txt(cnpj).up()
        .ele("xNome").txt(normalizeText(payload.emitente.razao_social)).up()
        .ele("enderEmit")
          .ele("xLgr").txt(normalizeText(payload.emitente.logradouro)).up()
          .ele("nro").txt(String(payload.emitente.numero || "SN")).up()
          .ele("xBairro").txt(normalizeText(payload.emitente.bairro)).up()
          .ele("cMun").txt("5212501").up()
          .ele("xMun").txt("LUZIANIA").up()
          .ele("UF").txt("GO").up()
          .ele("CEP").txt(onlyNumbers(payload.emitente.cep)).up()
          .ele("cPais").txt("1058").up()
          .ele("xPais").txt("BRASIL").up().up()
        .ele("IE").txt(onlyNumbers(payload.emitente.inscricao_estadual)).up()
        .ele("CRT").txt("1").up();

    payload.itens.forEach((item: any, i: number) => {
      const det = infNFe.ele("det", { nItem: String(i + 1) });
      const prod = det.ele("prod");
      prod.ele("cProd").txt(String(item.codigo_produto || i + 1)).up()
          .ele("cEAN").txt("SEM GTIN").up()
          .ele("xProd").txt(normalizeText(item.descricao)).up()
          .ele("NCM").txt(String(item.ncm || "21069090")).up()
          .ele("CFOP").txt("5102").up()
          .ele("uCom").txt(normalizeText(item.unidade, "UN")).up()
          .ele("qCom").txt(safeNumber(item.quantidade, 1).toFixed(4)).up()
          .ele("vUnCom").txt(safeNumber(item.valor_unitario).toFixed(2)).up()
          .ele("vProd").txt((safeNumber(item.quantidade, 1) * safeNumber(item.valor_unitario)).toFixed(2)).up()
          .ele("cEANTrib").txt("SEM GTIN").up()
          .ele("uTrib").txt(normalizeText(item.unidade, "UN")).up()
          .ele("qTrib").txt(safeNumber(item.quantidade, 1).toFixed(4)).up()
          .ele("vUnTrib").txt(safeNumber(item.valor_unitario).toFixed(2)).up()
          .ele("indTot").txt("1").up();
      
      const imp = det.ele("imposto");
      imp.ele("ICMS").ele("ICMSSN102").ele("orig").txt("0").up().ele("CSOSN").txt("102").up().up().up()
         .ele("PIS").ele("PISNT").ele("CST").txt("07").up().up().up()
         .ele("COFINS").ele("COFINSNT").ele("CST").txt("07").up();
    });

    const vTot = safeNumber(payload.totais.valor_total).toFixed(2);
    infNFe.ele("total").ele("ICMSTot")
      .ele("vBC").txt("0.00").up().ele("vICMS").txt("0.00").up()
      .ele("vProd").txt(vTot).up().ele("vNF").txt(vTot).up().up().up()
      .ele("transp").ele("modFrete").txt("9").up().up()
      .ele("pag").ele("detPag")
        .ele("tPag").txt(String(payload.pagamento.forma_codigo || "01")).up()
        .ele("vPag").txt(vTot).up();

    const sig = new SignedXml();
    sig.privateKey = keyPem;
    sig.publicCert = certPem;
    sig.addReference({ xpath: "//*[local-name(.)='infNFe']", transforms: ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"], digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256" });
    sig.computeSignature(xmlObj.end({ headless: true }), { location: { reference: "//*[local-name(.)='infNFe']", action: "after" } });

    const csc = payload.certificado.csc || payload.certificado.csc_token;
    const cscId = payload.certificado.csc_id;
    const qrCode = gerarQrCodeNfce(chave, tpAmb, String(cscId), String(csc));
    const urlC = tpAmb === 1 ? "https://nfe.sefaz.go.gov.br/nfeweb/sites/nfce/danfeNFCe" : "https://homolog.sefaz.go.gov.br/nfeweb/sites/nfce/danfeNFCe";
    
    const xmlFinal = sig.getSignedXml().replace("</NFe>", `<infNFeSupl><qrCode><![CDATA[${qrCode}]]></qrCode><urlChave>${urlC}</urlChave></infNFeSupl></NFe>`);
    const soap = `<?xml version="1.0" encoding="utf-8"?><soap12:Envelope xmlns:soap12="http://www.w3.org/2003/05/soap-envelope"><soap12:Body><nfeDadosMsg xmlns="http://www.portalfiscal.inf.br/nfe/wsdl/NFeAutorizacao4"><enviNFe xmlns="http://www.portalfiscal.inf.br/nfe" versao="4.00"><idLote>1</idLote><indSinc>1</indSinc>${xmlFinal}</enviNFe></nfeDadosMsg></soap12:Body></soap12:Envelope>`;

    const response = await axios.post(tpAmb === 1 ? SEFAZ_GO.autorizacaoProducao : SEFAZ_GO.autorizacaoHomologacao, soap, {
      httpsAgent: new https.Agent({ pfx: certBuffer, passphrase: String(payload.certificado.senha), rejectUnauthorized: false }),
      headers: { "Content-Type": "application/soap+xml; charset=utf-8" }
    });

    res.json({ autorizado: true, chave, sefaz: new XMLParser().parse(response.data) });
  } catch (err: any) {
    res.status(500).json({ autorizado: false, motivo: err.message });
  }
});

app.listen(PORT, () => console.log(`🚀 Luziânia na porta ${PORT}`));