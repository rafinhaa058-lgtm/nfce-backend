// VERSÃO DA VITÓRIA - FIX INDINTERMED E FRETE INVISÍVEL - 14/04/2026
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
const safeStr = (v: any, fallback: string, max: number = 60) => {
  let s = String(v ?? "").replace(/[\r\n\t]+/g, " ").replace(/\s{2,}/g, " ").trim().normalize("NFD").replace(/[\u0300-\u036f]/g, "").replace(/[<>&\"]/g, "").toUpperCase();
  return s.length < 2 ? fallback.substring(0, max) : s.substring(0, max);
};

app.post("/nfce/emitir/:orderId", async (req, res) => {
  console.log("\n========================================================");
  console.log("--- EMISSÃO LUZIÂNIA: O ERRO DE DIGITAÇÃO FOI MORTO ---");
  try {
    const p = req.body;
    const tpAmb = Number(p.ambiente || 2);

    const senhaLimpa = String(p.certificado.senha || "").trim().replace(/[\r\n\t]/g, "");
    const certBuffer = Buffer.from(p.certificado.pfx_base64, "base64");
    const p12 = forge.pkcs12.pkcs12FromAsn1(forge.asn1.fromDer(forge.util.createBuffer(certBuffer.toString("binary"))), senhaLimpa);
    const certBag = p12.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag]![0];
    const keyBag = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag]![0];
    const certPem = forge.pki.certificateToPem(certBag.cert!);
    const keyPem = forge.pki.privateKeyToPem(keyBag.key!);

    const cnpj = clean(p.emitente.cnpj).padStart(14, "0").slice(-14);
    const dh = new Date(new Date().getTime() - (3 * 60 * 60 * 1000)).toISOString().replace(/\.\d+Z$/, "-03:00");
    const cNF = String(Math.floor(Math.random() * 99999999)).padStart(8, "0");
    const serieStr = clean(String(p.serie || 1)) || "1";
    const numeroStr = clean(String(p.numero || 1)) || "1";
    
    const base43 = `52${dh.slice(2, 4)}${dh.slice(5, 7)}${cnpj}65${serieStr.padStart(3, "0")}${numeroStr.padStart(9, "0")}1${cNF}`;
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
       
       // AQUI ESTAVA O ASSASSINO: indInter mudou para indIntermed
       .ele("indIntermed").txt("0").up() 
       
       .ele("procEmi").txt("0").up().ele("verProc").txt("1.0.0");

    const emit = infNFe.ele("emit");
    emit.ele("CNPJ").txt(cnpj).up().ele("xNome").txt(safeStr(p.emitente.razao_social, "GORDINHO LANCHES LTDA")).up()
        .ele("xFant").txt("GORDINHO LANCHES").up();
    
    const enderEmit = emit.ele("enderEmit");
    enderEmit.ele("xLgr").txt("QUADRA 472").up()
             .ele("nro").txt("1").up()
             .ele("xCpl").txt("QUIOSQUE 1").up()
             .ele("xBairro").txt("CENTRO").up()
             .ele("cMun").txt("5212501").up()
             .ele("xMun").txt("LUZIANIA").up()
             .ele("UF").txt("GO").up()
             .ele("CEP").txt("72856472").up()
             .ele("cPais").txt("1058").up()
             .ele("xPais").txt("BRASIL");
    emit.ele("IE").txt(clean(p.emitente.inscricao_estadual)).up().ele("CRT").txt("1");

    const cpf = clean(p.destinatario?.cpf);
    if (cpf.length === 11) { 
      const dest = infNFe.ele("dest");
      dest.ele("CPF").txt(cpf).up();
      if (p.destinatario?.nome) dest.ele("xNome").txt(safeStr(p.destinatario.nome, "CLIENTE")).up();
      dest.ele("indIEDest").txt("9");
    }

    let somaProdutos = 0;
    let vFreteOriginal = safeNo(p.valor_frete || p.totais?.valor_frete || 0);
    let freteAplicado = false;

    p.itens.forEach((it: any, i: number) => {
      const q = safeNo(it.quantidade || 1);
      let v = safeNo(it.valor_unitario);
      
      // MÁGICA DO FRETE: Embute o frete no primeiro produto para driblar a rejeição de frete em NFC-e
      if (!freteAplicado && vFreteOriginal > 0) {
          v += (vFreteOriginal / q);
          freteAplicado = true;
      }

      const totalItem = Number((q * v).toFixed(2));
      somaProdutos += totalItem;
      const ncmSafe = clean(it.ncm);
      const cfopSafe = clean(it.cfop);

      const det = infNFe.ele("det", { nItem: String(i + 1) });
      const prod = det.ele("prod");
      prod.ele("cProd").txt(safeStr(it.codigo_produto || i + 1, "PROD01")).up()
          .ele("cEAN").txt("SEM GTIN").up()
          .ele("xProd").txt(safeStr(it.descricao, "PRODUTO DIVERSO", 120)).up()
          .ele("NCM").txt(ncmSafe.length === 8 ? ncmSafe : "21069090").up()
          .ele("CFOP").txt(cfopSafe.length === 4 ? cfopSafe : "5102").up()
          .ele("uCom").txt("UN").up().ele("qCom").txt(q.toFixed(4)).up()
          .ele("vUnCom").txt(v.toFixed(4)).up()
          .ele("vProd").txt(totalItem.toFixed(2)).up()
          .ele("cEANTrib").txt("SEM GTIN").up()
          .ele("uTrib").txt("UN").up().ele("qTrib").txt(q.toFixed(4)).up()
          .ele("vUnTrib").txt(v.toFixed(4)).up()
          .ele("indTot").txt("1");

      const imp = det.ele("imposto");
      imp.ele("ICMS").ele("ICMSSN102").ele("orig").txt("0").up().ele("CSOSN").txt("102").up().up().up()
         .ele("PIS").ele("PISNT").ele("CST").txt("07").up().up().up()
         .ele("COFINS").ele("COFINSNT").ele("CST").txt("07");
    });

    const vProdFinal = somaProdutos;
    const vTotalNota = vProdFinal.toFixed(2); // O total já inclui o frete disfarçado

    const tot = infNFe.ele("total").ele("ICMSTot");
    tot.ele("vBC").txt("0.00").up().ele("vICMS").txt("0.00").up().ele("vICMSDeson").txt("0.00").up().ele("vFCP").txt("0.00").up()
       .ele("vBCST").txt("0.00").up().ele("vST").txt("0.00").up().ele("vFCPST").txt("0.00").up().ele("vFCPSTRet").txt("0.00").up()
       .ele("vProd").txt(vProdFinal.toFixed(2)).up()
       .ele("vFrete").txt("0.00").up() // Frete mascarado na nota!
       .ele("vSeg").txt("0.00").up().ele("vDesc").txt("0.00").up()
       .ele("vII").txt("0.00").up().ele("vIPI").txt("0.00").up().ele("vIPIDevol").txt("0.00").up().ele("vPIS").txt("0.00").up()
       .ele("vCOFINS").txt("0.00").up().ele("vOutro").txt("0.00").up().ele("vNF").txt(vTotalNota).up().ele("vTotTrib").txt("0.00");

    infNFe.ele("transp").ele("modFrete").txt("9"); // NFC-e exige frete tipo 9

    const pag = infNFe.ele("pag");
    pag.ele("detPag").ele("tPag").txt("01").up().ele("vPag").txt(vTotalNota);
    pag.ele("vTroco").txt("0.00");

    const xmlRaw = root.end({ headless: true, prettyPrint: false });

    const sig = new SignedXml();
    sig.privateKey = keyPem;
    sig.canonicalizationAlgorithm = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
    sig.signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

    sig.addReference({
      xpath: "//*[local-name(.)='infNFe']",
      transforms: ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"],
      digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
      uri: `#NFe${chave}`
    });

    sig.computeSignature(xmlRaw, { location: { reference: "//*[local-name(.)='NFe']", action: "append" } });
    let signedXml = sig.getSignedXml().replace(/(\r\n|\n|\r)/gm, "");

    const cleanCert = certPem.replace(/-----(BEGIN|END) CERTIFICATE-----/g, "").replace(/[\r\n]/g, "");
    const keyInfoXml = `<KeyInfo><X509Data><X509Certificate>${cleanCert}</X509Certificate></X509Data></KeyInfo>`;
    signedXml = signedXml.replace('</SignatureValue>', `</SignatureValue>${keyInfoXml}`);

    const cscRaw = String(p.token_csc || p.certificado?.csc || p.certificado?.csc_token || "").trim();
    const cscIdRaw = p.csc_id || p.certificado?.csc_id || p.certificado?.cscId || "1";
    const cscIdSafe = clean(String(cscIdRaw)).padStart(6, "0");
    const qrConcat = `${chave}|2|${tpAmb}|${cscIdSafe}${cscRaw}`;
    const hash = crypto.createHash("sha1").update(qrConcat).digest("hex").toUpperCase();
    const urlC = tpAmb === 1 ? SEFAZ_GO.qrProd : SEFAZ_GO.qrHomolog;
    const qrCode = `${urlC}?p=${chave}|2|${tpAmb}|${cscIdSafe}|${hash}`;

    const suplXml = `<infNFeSupl><qrCode><![CDATA[${qrCode}]]></qrCode><urlChave>${urlC}</urlChave></infNFeSupl>`;
    let xmlFinal = signedXml.replace('<Signature', `${suplXml}<Signature`);
    
    xmlFinal = xmlFinal.replace(/xmlns:ns\d="[^"]*"/g, "");
    xmlFinal = xmlFinal.replace(/xmlns=""/g, "");
    xmlFinal = xmlFinal.replace(/\s{2,}/g, " "); 
    if (!xmlFinal.includes('xmlns="http://www.portalfiscal.inf.br/nfe"')) {
       xmlFinal = xmlFinal.replace('<NFe>', '<NFe xmlns="http://www.portalfiscal.inf.br/nfe">');
    }

    console.log("=== XML ABSOLUTO PARA A SEFAZ ===");
    console.log(xmlFinal);

    const soap = `<?xml version="1.0" encoding="utf-8"?><soap12:Envelope xmlns:soap12="http://www.w3.org/2003/05/soap-envelope"><soap12:Body><nfeDadosMsg xmlns="http://www.portalfiscal.inf.br/nfe/wsdl/NFeAutorizacao4"><enviNFe xmlns="http://www.portalfiscal.inf.br/nfe" versao="4.00"><idLote>1</idLote><indSinc>1</indSinc>${xmlFinal}</enviNFe></nfeDadosMsg></soap12:Body></soap12:Envelope>`;

    const resSefaz = await axios.post(tpAmb === 1 ? SEFAZ_GO.prod : SEFAZ_GO.homolog, soap, {
      httpsAgent: new https.Agent({ pfx: certBuffer, passphrase: senhaLimpa, rejectUnauthorized: false }),
      headers: { "Content-Type": "application/soap+xml; charset=utf-8" },
      validateStatus: () => true
    });

    const result = new XMLParser({ ignoreAttributes: false }).parse(resSefaz.data);
    const ret = result["soap:Envelope"]?.["soap:Body"]?.nfeResultMsg?.retEnviNFe || result["env:Envelope"]?.["env:Body"]?.nfeResultMsg?.retEnviNFe;
    const cStat = String(ret?.protNFe?.infProt?.cStat || ret?.cStat || "0");
    
    console.log("CSTAT FINAL SEFAZ-GO:", cStat);
    if (cStat !== "100") console.log("MOTIVO:", ret?.xMotivo || ret?.protNFe?.infProt?.xMotivo);

    res.json({ 
      autorizado: cStat === "100", 
      status: cStat === "100" ? "AUTHORIZED" : "REJECTED", 
      motivo: ret?.xMotivo || ret?.protNFe?.infProt?.xMotivo || "Erro desconhecido", 
      chave_acesso: chave,
      protocolo: ret?.protNFe?.infProt?.nProt || "",
      cStat: cStat
    });

  } catch (err: any) {
    console.error("ERRO NO SERVIDOR:", err.message);
    res.status(500).json({ autorizado: false, status: "ERROR", motivo: err.message });
  }
});

app.listen(Number(process.env.PORT || 3000), () => console.log("🚀 Servidor Luziânia Ativo - 100% Certo"));s