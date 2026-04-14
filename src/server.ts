// VERSÃO JÚNIOR - O ACHATADOR DE XML (14/04/2026)
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

const SEFAZ_GO = {
  prod: "https://nfe.sefaz.go.gov.br/nfe/services/NFeAutorizacao4",
  homolog: "https://homolog.sefaz.go.gov.br/nfe/services/NFeAutorizacao4",
  qrProd: "https://nfe.sefaz.go.gov.br/nfeweb/sites/nfce/danfeNFCe",
  qrHomolog: "https://homolog.sefaz.go.gov.br/nfeweb/sites/nfce/danfeNFCe",
};

const clean = (v: any) => String(v ?? "").replace(/\D/g, "");
const safeNo = (v: any) => { const n = Number(v); return Number.isFinite(n) ? n : 0; };
const norm = (v: any, max: number = 60) => String(v ?? "").trim().normalize("NFD").replace(/[\u0300-\u036f]/g, "").replace(/[<>&\"]/g, "").toUpperCase().substring(0, max);

app.post("/nfce/emitir/:orderId", async (req, res) => {
  console.log("--- EMISSÃO LUZIÂNIA: MODO XML ACHATADO ---");
  try {
    const p = req.body;
    const tpAmb = Number(p.ambiente || 2);

    const certBuffer = Buffer.from(p.certificado.pfx_base64, "base64");
    const p12 = forge.pkcs12.pkcs12FromAsn1(forge.asn1.fromDer(forge.util.createBuffer(certBuffer.toString("binary"))), String(p.certificado.senha));
    const certBag = p12.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag]![0];
    const keyBag = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag]![0];
    const certPem = forge.pki.certificateToPem(certBag.cert!);
    const keyPem = forge.pki.privateKeyToPem(keyBag.key!);

    const cnpj = clean(p.emitente.cnpj).padStart(14, "0").slice(-14);
    const dh = new Date(new Date().getTime() - (3 * 60 * 60 * 1000)).toISOString().replace(/\.\d+Z$/, "-03:00");
    const cNF = String(Math.floor(Math.random() * 99999999)).padStart(8, "0");
    const serieStr = clean(String(p.serie || 1)) || "1";
    const numeroStr = clean(String(p.numero || 1)) || "1";
    const seriePad = serieStr.padStart(3, "0");
    const nNFPad = numeroStr.padStart(9, "0");

    const base43 = `52${dh.slice(2, 4)}${dh.slice(5, 7)}${cnpj}65${seriePad}${nNFPad}1${cNF}`;
    let soma = 0, peso = 2;
    for (let i = base43.length - 1; i >= 0; i--) { soma += Number(base43[i]) * peso; peso = peso === 9 ? 2 : peso + 1; }
    const dv = (soma % 11 === 0 || soma % 11 === 1) ? "0" : String(11 - (soma % 11));
    const chave = base43 + dv;

    const root = create({ version: "1.0", encoding: "UTF-8" }).ele("NFe", { xmlns: "http://www.portalfiscal.inf.br/nfe" });
    const infNFe = root.ele("infNFe", { versao: "4.00", Id: `NFe${chave}` });

    const ide = infNFe.ele("ide");
    ide.ele("cUF").txt("52").up().ele("cNF").txt(cNF).up().ele("natOp").txt("VENDA").up().ele("mod").txt("65").up()
       .ele("serie").txt(serieStr).up().ele("nNF").txt(numeroStr).up().ele("dhEmi").txt(dh).up()
       .ele("tpNF").txt("1").up().ele("idDest").txt("1").up().ele("cMunFG").txt("5212501").up().ele("tpImp").txt("4").up()
       .ele("tpEmis").txt("1").up().ele("cDV").txt(dv).up().ele("tpAmb").txt(String(tpAmb)).up()
       .ele("finNFe").txt("1").up().ele("indFinal").txt("1").up().ele("indPres").txt("1").up()
       .ele("indInter").txt("0").up().ele("procEmi").txt("0").up().ele("verProc").txt("1.0.0");

    const emit = infNFe.ele("emit");
    emit.ele("CNPJ").txt(cnpj).up().ele("xNome").txt(norm(p.emitente.razao_social)).up();
    if (p.emitente.nome_fantasia) emit.ele("xFant").txt(norm(p.emitente.nome_fantasia)).up();
    
    const enderEmit = emit.ele("enderEmit");
    enderEmit.ele("xLgr").txt(norm(p.emitente.logradouro)).up().ele("nro").txt(norm(p.emitente.numero || "SN")).up();
    const cepOk = clean(p.emitente.cep).padStart(8, "0").slice(-8);
    enderEmit.ele("xBairro").txt(norm(p.emitente.bairro || "CENTRO")).up().ele("cMun").txt("5212501").up()
             .ele("xMun").txt("LUZIANIA").up().ele("UF").txt("GO").up().ele("CEP").txt(cepOk).up()
             .ele("cPais").txt("1058").up().ele("xPais").txt("BRASIL");
    emit.ele("IE").txt(clean(p.emitente.inscricao_estadual)).up().ele("CRT").txt("1");

    p.itens.forEach((it: any, i: number) => {
      const q = safeNo(it.quantidade || 1);
      const v = safeNo(it.valor_unitario);
      const det = infNFe.ele("det", { nItem: String(i + 1) });
      const prod = det.ele("prod");
      prod.ele("cProd").txt(norm(it.codigo_produto || i + 1, 60)).up().ele("cEAN").txt("SEM GTIN").up()
          .ele("xProd").txt(norm(it.descricao || "PRODUTO", 120)).up().ele("NCM").txt("21069090").up()
          .ele("CFOP").txt("5102").up().ele("uCom").txt("UN").up().ele("qCom").txt(q.toFixed(4)).up()
          .ele("vUnCom").txt(v.toFixed(2)).up().ele("vProd").txt((q * v).toFixed(2)).up()
          .ele("cEANTrib").txt("SEM GTIN").up().ele("uTrib").txt("UN").up().ele("qTrib").txt(q.toFixed(4)).up()
          .ele("vUnTrib").txt(v.toFixed(2)).up().ele("indTot").txt("1");

      const imp = det.ele("imposto");
      imp.ele("ICMS").ele("ICMSSN102").ele("orig").txt("0").up().ele("CSOSN").txt("102").up().up().up()
         .ele("PIS").ele("PISNT").ele("CST").txt("07").up().up().up()
         .ele("COFINS").ele("COFINSNT").ele("CST").txt("07");
    });

    const vTotal = safeNo(p.totais.valor_total).toFixed(2);
    const tot = infNFe.ele("total").ele("ICMSTot");
    tot.ele("vBC").txt("0.00").up().ele("vICMS").txt("0.00").up().ele("vICMSDeson").txt("0.00").up().ele("vFCP").txt("0.00").up()
       .ele("vBCST").txt("0.00").up().ele("vST").txt("0.00").up().ele("vFCPST").txt("0.00").up().ele("vFCPSTRet").txt("0.00").up()
       .ele("vProd").txt(vTotal).up().ele("vFrete").txt("0.00").up().ele("vSeg").txt("0.00").up().ele("vDesc").txt("0.00").up()
       .ele("vII").txt("0.00").up().ele("vIPI").txt("0.00").up().ele("vIPIDevol").txt("0.00").up().ele("vPIS").txt("0.00").up()
       .ele("vCOFINS").txt("0.00").up().ele("vOutro").txt("0.00").up().ele("vNF").txt(vTotal); // Removido vTotTrib (opcional que causa erro)

    infNFe.ele("transp").ele("modFrete").txt("9");
    const pag = infNFe.ele("pag");
    pag.ele("detPag").ele("tPag").txt(String(p.pagamento?.forma_codigo || "01").padStart(2, "0")).up().ele("vPag").txt(vTotal);

    const csc = String(p.certificado.csc || p.certificado.csc_token).trim();
    const cscId = String(p.certificado.csc_id).padStart(6, "0");
    const hash = crypto.createHash("sha1").update(`${chave}|2|${tpAmb}|${cscId}${csc}`).digest("hex").toUpperCase();
    const urlC = tpAmb === 1 ? SEFAZ_GO.qrProd : SEFAZ_GO.qrHomolog;
    const qrCode = `${urlC}?p=${chave}|2|${tpAmb}|${cscId}|${hash}`;

    const supl = root.ele("infNFeSupl");
    supl.ele("qrCode").txt(qrCode).up().ele("urlChave").txt(urlC);

    // O SEGREDO: prettyPrint false cria uma linha só de XML, sem quebras que destroem a assinatura
    const xmlRaw = root.end({ headless: true, prettyPrint: false });

    const sig = new SignedXml();
    sig.privateKey = keyPem;
    sig.publicCert = certPem;
    sig.canonicalizationAlgorithm = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
    sig.signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    sig.addReference({
      xpath: "//*[local-name(.)='infNFe']",
      transforms: ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"],
      digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
      uri: `#NFe${chave}`
    });

    sig.computeSignature(xmlRaw, { location: { reference: "//*[local-name(.)='NFe']", action: "append" } });
    
    // Força a remoção de TODAS as quebras de linha invisíveis que a biblioteca de assinatura cria
    let xmlFinal = sig.getSignedXml().replace(/(\r\n|\n|\r)/gm, "");
    xmlFinal = xmlFinal.replace(/<NFe>/, '<NFe xmlns="http://www.portalfiscal.inf.br/nfe">');

    const soap = `<?xml version="1.0" encoding="utf-8"?><soap12:Envelope xmlns:soap12="http://www.w3.org/2003/05/soap-envelope"><soap12:Header/><soap12:Body><nfeDadosMsg xmlns="http://www.portalfiscal.inf.br/nfe/wsdl/NFeAutorizacao4"><enviNFe xmlns="http://www.portalfiscal.inf.br/nfe" versao="4.00"><idLote>1</idLote><indSinc>1</indSinc>${xmlFinal}</enviNFe></nfeDadosMsg></soap12:Body></soap12:Envelope>`;

    const resSefaz = await axios.post(tpAmb === 1 ? SEFAZ_GO.prod : SEFAZ_GO.homolog, soap, {
      httpsAgent: new https.Agent({ pfx: certBuffer, passphrase: String(p.certificado.senha), rejectUnauthorized: false }),
      headers: { "Content-Type": "application/soap+xml; charset=utf-8" },
      validateStatus: () => true
    });

    console.log("=== RESPOSTA SEFAZ-GO ACHATADA ===");
    console.log(resSefaz.data);

    const result = new XMLParser({ ignoreAttributes: false }).parse(resSefaz.data);
    const ret = result["soap:Envelope"]?.["soap:Body"]?.nfeResultMsg?.retEnviNFe || result["env:Envelope"]?.["env:Body"]?.nfeResultMsg?.retEnviNFe;
    const cStat = String(ret?.protNFe?.infProt?.cStat || ret?.cStat || "0");
    
    console.log("CSTAT FINAL SEFAZ-GO:", cStat);

    res.json({ 
      autorizado: cStat === "100", 
      status: cStat === "100" ? "AUTHORIZED" : "REJECTED", 
      motivo: ret?.xMotivo || ret?.protNFe?.infProt?.xMotivo || "Erro", 
      chave_acesso: chave,
      cStat: cStat
    });

  } catch (err: any) {
    console.error("ERRO NO SERVIDOR:", err.message);
    res.status(500).json({ autorizado: false, status: "ERROR", motivo: err.message });
  }
});

app.listen(Number(process.env.PORT || 3000), () => console.log("🚀 Servidor Luziânia Ativo - Modo Júnior"));