// VERSÃO BLINDADA - 14/04/2026 17:00
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import forge from "node-forge";
import { create } from "xmlbuilder2";
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
const onlyNumbers = (v: any) => String(v ?? "").replace(/\D/g, "");
const safeNumber = (v: any) => { const n = Number(v); return Number.isFinite(n) ? n : 0; };
const normalize = (v: any) => String(v ?? "").trim().normalize("NFD").replace(/[\u0300-\u036f]/g, "").replace(/[<&"'>]/g, "").toUpperCase();

function formatarDataSefaz(data?: any): string {
  const local = data ? new Date(data) : new Date();
  const d = new Date(local.getTime() - (3 * 60 * 60 * 1000));
  return d.toISOString().replace(/\.\d+Z$/, "-03:00");
}

function calcularDV(c: string): string {
  let p = 2, s = 0;
  for (let i = c.length - 1; i >= 0; i--) { s += Number(c[i]) * p; p = p === 9 ? 2 : p + 1; }
  const m = s % 11; return (m === 0 || m === 1) ? "0" : String(11 - m);
}

// --- EMISSÃO ---
app.post("/nfce/emitir/:orderId", async (req, res) => {
  console.log("--- INICIANDO EMISSÃO NFC-E LUZIÂNIA ---");
  try {
    const p = req.body;
    const tpAmb = Number(p.ambiente || 2);

    // 1. Certificado
    const certBuffer = Buffer.from(p.certificado.pfx_base64, "base64");
    const p12 = forge.pkcs12.pkcs12FromAsn1(forge.asn1.fromDer(forge.util.createBuffer(certBuffer.toString("binary"))), String(p.certificado.senha));
    const certBag = p12.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag]![0];
    const keyBag = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag]![0];
    const certPem = forge.pki.certificateToPem(certBag.cert!);
    const keyPem = forge.pki.privateKeyToPem(keyBag.key!);

    // 2. Chave de Acesso
    const cnpj = onlyNumbers(p.emitente.cnpj);
    const dh = formatarDataSefaz(p.data_emissao);
    const cNF = String(Math.floor(Math.random() * 99999999)).padStart(8, "0");
    const base43 = `52${dh.slice(2, 4)}${dh.slice(5, 7)}${cnpj.padStart(14, "0")}65${String(p.serie || 1).padStart(3, "0")}${String(p.numero || 1).padStart(9, "0")}1${cNF}`;
    const chave = `${base43}${calcularDV(base43)}`;

    // 3. Construção do XML (Fix TypeScript TS2349)
    const xmlDoc = create({ version: "1.0", encoding: "UTF-8" }).ele("NFe", { xmlns: "http://www.portalfiscal.inf.br/nfe" });
    const infNFe = xmlDoc.ele("infNFe", { versao: "4.00", Id: `NFe${chave}` });

    // IDE
    const ide = infNFe.ele("ide");
    ide.ele("cUF").txt("52").up().ele("cNF").txt(cNF).up().ele("natOp").txt("VENDA").up().ele("mod").txt("65").up()
       .ele("serie").txt(String(p.serie || 1)).up().ele("nNF").txt(String(p.numero || 1)).up().ele("dhEmi").txt(dh).up()
       .ele("tpNF").txt("1").up().ele("idDest").txt("1").up().ele("cMunFG").txt("5212501").up().ele("tpImp").txt("4").up()
       .ele("tpEmis").txt("1").up().ele("cDV").txt(chave.slice(-1)).up().ele("tpAmb").txt(String(tpAmb)).up()
       .ele("finNFe").txt("1").up().ele("indFinal").txt("1").up().ele("indPres").txt("1").up().ele("procEmi").txt("0").up()
       .ele("verProc").txt("1.0.0");

    // EMIT
    const emit = infNFe.ele("emit");
    emit.ele("CNPJ").txt(cnpj).up().ele("xNome").txt(normalize(p.emitente.razao_social)).up()
        .ele("enderEmit")
          .ele("xLgr").txt(normalize(p.emitente.logradouro)).up().ele("nro").txt(String(p.emitente.numero || "SN")).up()
          .ele("xBairro").txt(normalize(p.emitente.bairro)).up().ele("cMun").txt("5212501").up().ele("xMun").txt("LUZIANIA").up()
          .ele("UF").txt("GO").up().ele("CEP").txt(onlyNumbers(p.emitente.cep)).up().ele("cPais").txt("1058").up().ele("xPais").txt("BRASIL");
    emit.up().ele("IE").txt(onlyNumbers(p.emitente.inscricao_estadual)).up().ele("CRT").txt("1");

    // ITENS
    p.itens.forEach((it: any, i: number) => {
      const det = infNFe.ele("det", { nItem: String(i + 1) });
      const prod = det.ele("prod");
      prod.ele("cProd").txt(String(it.codigo_produto || i + 1)).up().ele("cEAN").txt("SEM GTIN").up().ele("xProd").txt(normalize(it.descricao)).up()
          .ele("NCM").txt("21069090").up().ele("CFOP").txt("5102").up().ele("uCom").txt("UN").up().ele("qCom").txt(safeNumber(it.quantidade).toFixed(4)).up()
          .ele("vUnCom").txt(safeNumber(it.valor_unitario).toFixed(2)).up().ele("vProd").txt((safeNumber(it.quantidade) * safeNumber(it.valor_unitario)).toFixed(2)).up()
          .ele("cEANTrib").txt("SEM GTIN").up().ele("uTrib").txt("UN").up().ele("qTrib").txt(safeNumber(it.quantidade).toFixed(4)).up().ele("vUnTrib").txt(safeNumber(it.valor_unitario).toFixed(2)).up().ele("indTot").txt("1");
      
      const imp = det.ele("imposto");
      imp.ele("ICMS").ele("ICMSSN102").ele("orig").txt("0").up().ele("CSOSN").txt("102");
      imp.up().up().ele("PIS").ele("PISNT").ele("CST").txt("07");
      imp.up().up().ele("COFINS").ele("COFINSNT").ele("CST").txt("07");
    });

    // TOTAL
    const totalV = safeNumber(p.totais.valor_total).toFixed(2);
    const total = infNFe.ele("total").ele("ICMSTot");
    total.ele("vBC").txt("0.00").up().ele("vICMS").txt("0.00").up().ele("vProd").txt(totalV).up().ele("vNF").txt(totalV);

    // TRANSP / PAG
    infNFe.ele("transp").ele("modFrete").txt("9");
    infNFe.ele("pag").ele("detPag").ele("tPag").txt(String(p.pagamento.forma_codigo || "01")).up().ele("vPag").txt(totalV);

    // 4. Assinatura Digital
    const sig = new SignedXml();
    sig.privateKey = keyPem;
    sig.publicCert = certPem;
    sig.canonicalizationAlgorithm = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
    sig.signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    sig.addReference({ xpath: "//*[local-name(.)='infNFe']", transforms: ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"], digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256" });
    
    const xmlAssinaturaBase = xmlDoc.end({ headless: true });
    sig.computeSignature(xmlAssinaturaBase, { location: { reference: "//*[local-name(.)='infNFe']", action: "after" } });

    // 5. QR Code NFC-e
    const csc = p.certificado.csc || p.certificado.csc_token;
    const cscId = String(p.certificado.csc_id).padStart(6, "0");
    const hash = crypto.createHash("sha1").update(`${chave}|2|${tpAmb}|${cscId}${csc}`).digest("hex").toUpperCase();
    const urlC = tpAmb === 1 ? "https://nfe.sefaz.go.gov.br/nfeweb/sites/nfce/danfeNFCe" : "https://homolog.sefaz.go.gov.br/nfeweb/sites/nfce/danfeNFCe";
    const qrCode = `${urlC}?p=${chave}|2|${tpAmb}|${cscId}|${hash}`;

    const xmlFinal = sig.getSignedXml().replace("</NFe>", `<infNFeSupl><qrCode><![CDATA[${qrCode}]]></qrCode><urlChave>${urlC}</urlChave></infNFeSupl></NFe>`);
    
    // 6. Envio SOAP
    const soap = `<?xml version="1.0" encoding="utf-8"?><soap12:Envelope xmlns:soap12="http://www.w3.org/2003/05/soap-envelope"><soap12:Body><nfeDadosMsg xmlns="http://www.portalfiscal.inf.br/nfe/wsdl/NFeAutorizacao4"><enviNFe xmlns="http://www.portalfiscal.inf.br/nfe" versao="4.00"><idLote>1</idLote><indSinc>1</indSinc>${xmlFinal}</enviNFe></nfeDadosMsg></soap12:Body></soap12:Envelope>`;

    const resSefaz = await axios.post(tpAmb === 1 ? SEFAZ_GO.autorizacaoProducao : SEFAZ_GO.autorizacaoHomologacao, soap, {
      httpsAgent: new https.Agent({ pfx: certBuffer, passphrase: String(p.certificado.senha), rejectUnauthorized: false }),
      headers: { "Content-Type": "application/soap+xml; charset=utf-8" },
      validateStatus: () => true
    });

    console.log("RESPOSTA SEFAZ:", JSON.stringify(new XMLParser().parse(resSefaz.data)));
    res.json({ autorizado: resSefaz.status === 200, sefaz: new XMLParser().parse(resSefaz.data) });

  } catch (err: any) {
    console.error("ERRO:", err.message);
    res.status(500).json({ autorizado: false, motivo: err.message });
  }
});

app.get("/", (req, res) => res.send("NFC-e Luziânia Ativo!"));
app.listen(PORT, () => console.log(`🚀 Porta ${PORT}`));