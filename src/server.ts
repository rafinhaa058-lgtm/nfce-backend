// VERSÃO REVISADA - 14/04/2026 16:35 - LUZIÂNIA-GO
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import forge from "node-forge";
import { create } from "xmlbuilder2";
import PDFDocument from "pdfkit";
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

function onlyNumbers(value: unknown): string {
  return String(value ?? "").replace(/\D/g, "");
}

function safeNumber(value: unknown, fallback = 0): number {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function normalizeText(value: unknown, fallback = ""): string {
  let text = String(value ?? fallback).trim();
  text = text.normalize("NFD").replace(/[\u0300-\u036f]/g, ""); // Remove acentos de "Luziânia", etc.
  return text.replace(/[<&"'>]/g, "").toUpperCase() || fallback;
}

function pad(value: string | number, size: number): string {
  return String(value).padStart(size, "0");
}

function formatarDataSefaz(data?: string | Date): string {
  const local = data ? new Date(data) : new Date();
  const offset = -3; // Fuso de Brasília
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

// --- NFC-E ESPECÍFICO (QR CODE) ---

function gerarQrCodeNfce(chave: string, ambiente: number, cscId: string, csc: string): string {
  const urlBase = ambiente === 1 
    ? "https://nfe.sefaz.go.gov.br/nfeweb/sites/nfce/danfeNFCe"
    : "https://homolog.sefaz.go.gov.br/nfeweb/sites/nfce/danfeNFCe";

  const cIdToken = pad(onlyNumbers(cscId), 6);
  const concat = `${chave}|2|${ambiente}|${cIdToken}${csc}`;
  const hash = crypto.createHash("sha1").update(concat).digest("hex").toUpperCase();
  
  return `${urlBase}?p=${chave}|2|${ambiente}|${cIdToken}|${hash}`;
}

// --- LÓGICA DE EMISSÃO ---

app.post("/nfce/emitir/:orderId", async (req, res) => {
  try {
    const payload = req.body;
    const tpAmb = Number(payload.ambiente || 2);
    
    // 1. Validar Certificado
    if (!payload.certificado?.pfx_base64) throw new Error("PFX do certificado ausente.");
    const certBuffer = Buffer.from(payload.certificado.pfx_base64, "base64");
    const p12Der = forge.util.createBuffer(certBuffer.toString("binary"));
    const p12 = forge.pkcs12.pkcs12FromAsn1(forge.asn1.fromDer(p12Der), String(payload.certificado.senha));
    
    const certBag = p12.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag]![0];
    const keyBag = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag]![0];
    
    const certPem = forge.pki.certificateToPem(certBag.cert!);
    const keyPem = forge.pki.privateKeyToPem(keyBag.key!);

    // 2. Montar XML Base
    const cnpj = onlyNumbers(payload.emitente.cnpj);
    const dhEmi = formatarDataSefaz(payload.data_emissao);
    const cNF = pad(Math.floor(Math.random() * 99999999), 8);
    const serie = pad(payload.serie || 1, 3);
    const nNF = pad(payload.numero || 1, 9);
    
    const base43 = `52${dhEmi.slice(2, 4)}${dhEmi.slice(5, 7)}${cnpj.padStart(14, "0")}65${serie}${nNF}1${cNF}`;
    const chave = `${base43}${calcularDVChave(base43)}`;

    const xmlObj = create({ version: "1.0", encoding: "UTF-8" })
      .ele("NFe", { xmlns: "http://www.portalfiscal.inf.br/nfe" })
        .ele("infNFe", { versao: "4.00", Id: `NFe${chave}` })
          .ele("ide")
            .ele("cUF").txt("52").up()
            .ele("cNF").txt(cNF).up()
            .ele("natOp").txt(normalizeText(payload.natureza_operacao, "VENDA")).up()
            .ele("mod").txt("65").up()
            .ele("serie").txt(payload.serie || 1).up()
            .ele("nNF").txt(payload.numero || 1).up()
            .ele("dhEmi").txt(dhEmi).up()
            .ele("tpNF").txt("1").up()
            .ele("idDest").txt("1").up()
            .ele("cMunFG").txt("5212501").up()
            .ele("tpImp").txt("4").up()
            .ele("tpEmis").txt("1").up()
            .ele("cDV").txt(chave.slice(-1)).up()
            .ele("tpAmb").txt(tpAmb).up()
            .ele("finNFe").txt("1").up()
            .ele("indFinal").txt("1").up()
            .ele("indPres").txt("1").up()
            .ele("procEmi").txt("0").up()
            .ele("verProc").txt("1.0.0").up().up()
          .ele("emit")
            .ele("CNPJ").txt(cnpj).up()
            .ele("xNome").txt(normalizeText(payload.emitente.razao_social)).up()
            .ele("enderEmit")
              .ele("xLgr").txt(normalizeText(payload.emitente.logradouro)).up()
              .ele("nro").txt(payload.emitente.numero || "SN").up()
              .ele("xBairro").txt(normalizeText(payload.emitente.bairro)).up()
              .ele("cMun").txt("5212501").up()
              .ele("xMun").txt("LUZIANIA").up()
              .ele("UF").txt("GO").up()
              .ele("CEP").txt(onlyNumbers(payload.emitente.cep)).up()
              .ele("cPais").txt("1058").up()
              .ele("xPais").txt("BRASIL").up().up()
            .ele("IE").txt(onlyNumbers(payload.emitente.inscricao_estadual)).up()
            .ele("CRT").txt("1").up().up();

    // Adicionar Itens
    payload.itens.forEach((item: any, i: number) => {
      const det = xmlObj.node().ele("det", { nItem: i + 1 });
      const prod = det.ele("prod");
      prod.ele("cProd").txt(item.codigo_produto || i + 1).up();
      prod.ele("cEAN").txt("SEM GTIN").up();
      prod.ele("xProd").txt(normalizeText(item.descricao)).up();
      prod.ele("NCM").txt(item.ncm || "21069090").up();
      prod.ele("CFOP").txt("5102").up();
      prod.ele("uCom").txt(item.unidade || "UN").up();
      prod.ele("qCom").txt(safeNumber(item.quantidade, 1).toFixed(4)).up();
      prod.ele("vUnCom").txt(safeNumber(item.valor_unitario).toFixed(2)).up();
      prod.ele("vProd").txt((safeNumber(item.quantidade, 1) * safeNumber(item.valor_unitario)).toFixed(2)).up();
      prod.ele("cEANTrib").txt("SEM GTIN").up();
      prod.ele("uTrib").txt(item.unidade || "UN").up();
      prod.ele("qTrib").txt(safeNumber(item.quantidade, 1).toFixed(4)).up();
      prod.ele("vUnTrib").txt(safeNumber(item.valor_unitario).toFixed(2)).up();
      prod.ele("indTot").txt("1").up().up();
      
      const imp = det.ele("imposto");
      imp.ele("ICMS").ele("ICMSSN102").ele("orig").txt("0").up().ele("CSOSN").txt("102").up().up().up();
      imp.ele("PIS").ele("PISNT").ele("CST").txt("07").up().up().up();
      imp.ele("COFINS").ele("COFINSNT").ele("CST").txt("07").up().up().up();
    });

    const vTot = safeNumber(payload.totais.valor_total).toFixed(2);
    xmlObj.node().ele("total").ele("ICMSTot")
      .ele("vBC").txt("0.00").up().ele("vICMS").txt("0.00").up()
      .ele("vProd").txt(vTot).up().ele("vNF").txt(vTot).up().up().up()
      .ele("transp").ele("modFrete").txt("9").up().up()
      .ele("pag").ele("detPag")
        .ele("tPag").txt(payload.pagamento.forma_codigo || "01").up()
        .ele("vPag").txt(vTot).up().up().up();

    // 3. Assinar
    let xmlAssinado = new SignedXml();
    xmlAssinado.privateKey = keyPem;
    xmlAssinado.publicCert = certPem;
    xmlAssinado.addReference({
      xpath: "//*[local-name(.)='infNFe']",
      transforms: ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"],
      digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256"
    });
    xmlAssinado.computeSignature(xmlObj.end({ headless: true }), { location: { reference: "//*[local-name(.)='infNFe']", action: "after" } });

    // 4. Injetar Suplemento (QR Code) - ISSO CORRIGE O ERRO 225
    const csc = payload.certificado.csc || payload.certificado.csc_token;
    const cscId = payload.certificado.csc_id;
    if (!csc || !cscId) throw new Error("CSC ausente para NFC-e.");

    const qrCode = gerarQrCodeNfce(chave, tpAmb, cscId, csc);
    const urlConsulta = tpAmb === 1 ? "https://nfe.sefaz.go.gov.br/nfeweb/sites/nfce/danfeNFCe" : "https://homolog.sefaz.go.gov.br/nfeweb/sites/nfce/danfeNFCe";
    
    const suplemento = `<infNFeSupl><qrCode><![CDATA[${qrCode}]]></qrCode><urlChave>${urlConsulta}</urlChave></infNFeSupl>`;
    const xmlFinal = xmlAssinado.getSignedXml().replace("</NFe>", `${suplemento}</NFe>`);

    // 5. Enviar SOAP
    const soap = `<?xml version="1.0" encoding="utf-8"?><soap12:Envelope xmlns:soap12="http://www.w3.org/2003/05/soap-envelope"><soap12:Body><nfeDadosMsg xmlns="http://www.portalfiscal.inf.br/nfe/wsdl/NFeAutorizacao4"><enviNFe xmlns="http://www.portalfiscal.inf.br/nfe" versao="4.00"><idLote>1</idLote><indSinc>1</indSinc>${xmlFinal}</enviNFe></nfeDadosMsg></soap12:Body></soap12:Envelope>`;

    const agent = new https.Agent({ pfx: certBuffer, passphrase: payload.certificado.senha, rejectUnauthorized: false });
    const response = await axios.post(tpAmb === 1 ? SEFAZ_GO.autorizacaoProducao : SEFAZ_GO.autorizacaoHomologacao, soap, {
      httpsAgent: agent,
      headers: { "Content-Type": "application/soap+xml; charset=utf-8" }
    });

    const parser = new XMLParser({ ignoreAttributes: false });
    const resSefaz = parser.parse(response.data);
    
    res.json({ autorizado: true, chave, sefaz: resSefaz });

  } catch (err: any) {
    console.error(err);
    res.status(500).json({ autorizado: false, motivo: err.message });
  }
});

app.listen(PORT, () => console.log(`🚀 Servidor Fiscal em Luziânia porta ${PORT}`));