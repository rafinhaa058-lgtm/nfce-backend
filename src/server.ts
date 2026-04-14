// VERSÃO 100% RIGOROSA - 14/04/2026 17:30
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
};

const onlyNo = (v: any) => String(v ?? "").replace(/\D/g, "");
const safeNo = (v: any) => { const n = Number(v); return Number.isFinite(n) ? n : 0; };
const norm = (v: any) => String(v ?? "").trim().normalize("NFD").replace(/[\u0300-\u036f]/g, "").replace(/[#&"'<>]/g, "").toUpperCase();

app.post("/nfce/emitir/:orderId", async (req, res) => {
  console.log("--- TENTATIVA DE EMISSÃO NFC-E (LUZIÂNIA DELIVERY) ---");
  try {
    const p = req.body;
    const tpAmb = Number(p.ambiente || 2);

    // 1. CERTIFICADO
    const certBuffer = Buffer.from(p.certificado.pfx_base64, "base64");
    const p12 = forge.pkcs12.pkcs12FromAsn1(forge.asn1.fromDer(forge.util.createBuffer(certBuffer.toString("binary"))), String(p.certificado.senha));
    const certBag = p12.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag]![0];
    const keyBag = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag]![0];
    const certPem = forge.pki.certificateToPem(certBag.cert!);
    const keyPem = forge.pki.privateKeyToPem(keyBag.key!);

    // 2. CHAVE
    const cnpj = onlyNo(p.emitente.cnpj);
    const dh = new Date(new Date().getTime() - (3 * 60 * 60 * 1000)).toISOString().replace(/\.\d+Z$/, "-03:00");
    const cNF = String(Math.floor(Math.random() * 99999999)).padStart(8, "0");
    const base43 = `52${dh.slice(2, 4)}${dh.slice(5, 7)}${cnpj.padStart(14, "0")}65${String(p.serie || 1).padStart(3, "0")}${String(p.numero || 1).padStart(9, "0")}1${cNF}`;
    let soma = 0, peso = 2;
    for (let i = base43.length - 1; i >= 0; i--) { soma += Number(base43[i]) * peso; peso = peso === 9 ? 2 : peso + 1; }
    const dv = (soma % 11 === 0 || soma % 11 === 1) ? "0" : String(11 - (soma % 11));
    const chave = base43 + dv;
    const nfeId = `NFe${chave}`;

    // 3. XML (CONSTRUÇÃO COM ORDEM ESTADUAL GO)
    const xml = create({ version: "1.0", encoding: "UTF-8" }).ele("NFe", { xmlns: "http://www.portalfiscal.inf.br/nfe" });
    const inf = xml.ele("infNFe", { versao: "4.00", Id: nfeId });

    const ide = inf.ele("ide");
    ide.ele("cUF").txt("52").up().ele("cNF").txt(cNF).up().ele("natOp").txt("VENDA").up().ele("mod").txt("65").up()
       .ele("serie").txt(String(p.serie || 1)).up().ele("nNF").txt(String(p.numero || 1)).up().ele("dhEmi").txt(dh).up()
       .ele("tpNF").txt("1").up().ele("idDest").txt("1").up().ele("cMunFG").txt("5212501").up().ele("tpImp").txt("4").up()
       .ele("tpEmis").txt("1").up().ele("cDV").txt(dv).up().ele("tpAmb").txt(String(tpAmb)).up()
       .ele("finNFe").txt("1").up().ele("indFinal").txt("1").up().ele("indPres").txt("4").up() // 4 = Delivery
       .ele("procEmi").txt("0").up().ele("verProc").txt("1.0.0");

    const emit = inf.ele("emit");
    emit.ele("CNPJ").txt(cnpj).up().ele("xNome").txt(norm(p.emitente.razao_social)).up();
    const ender = emit.ele("enderEmit");
    ender.ele("xLgr").txt(norm(p.emitente.logradouro)).up().ele("nro").txt(norm(p.emitente.numero || "SN")).up()
         .ele("xBairro").txt(norm(p.emitente.bairro || "CENTRO")).up().ele("cMun").txt("5212501").up().ele("xMun").txt("LUZIANIA").up()
         .ele("UF").txt("GO").up().ele("CEP").txt(onlyNo(p.emitente.cep)).up().ele("cPais").txt("1058").up().ele("xPais").txt("BRASIL");
    emit.ele("IE").txt(onlyNo(p.emitente.inscricao_estadual)).up().ele("CRT").txt("1");

    if (onlyNo(p.destinatario?.cpf)) {
      inf.ele("dest").ele("CPF").txt(onlyNo(p.destinatario.cpf)).up().ele("indIEDest").txt("9").up().up();
    }

    p.itens.forEach((it: any, i: number) => {
      const det = inf.ele("det", { nItem: i + 1 });
      const prod = det.ele("prod");
      prod.ele("cProd").txt(norm(it.codigo_produto || i + 1)).up().ele("cEAN").txt("SEM GTIN").up().ele("xProd").txt(norm(it.descricao)).up()
          .ele("NCM").txt("21069090").up().ele("CFOP").txt("5102").up().ele("uCom").txt("UN").up().ele("qCom").txt(safeNo(it.quantidade).toFixed(4)).up()
          .ele("vUnCom").txt(safeNo(it.valor_unitario).toFixed(2)).up().ele("vProd").txt((safeNo(it.quantidade) * safeNo(it.valor_unitario)).toFixed(2)).up()
          .ele("cEANTrib").txt("SEM GTIN").up().ele("uTrib").txt("UN").up().ele("qTrib").txt(safeNo(it.quantidade).toFixed(4)).up()
          .ele("vUnTrib").txt(safeNo(it.valor_unitario).toFixed(2)).up().ele("indTot").txt("1");
      
      const imp = det.ele("imposto");
      imp.ele("ICMS").ele("ICMSSN102").ele("orig").txt("0").up().ele("CSOSN").txt("102").up().up().up()
         .ele("PIS").ele("PISNT").ele("CST").txt("07").up().up().up()
         .ele("COFINS").ele("COFINSNT").ele("CST").txt("07");
    });

    const vT = safeNo(p.totais.valor_total).toFixed(2);
    const tot = inf.ele("total").ele("ICMSTot");
    tot.ele("vBC").txt("0.00").up().ele("vICMS").txt("0.00").up().ele("vICMSDeson").txt("0.00").up().ele("vFCP").txt("0.00").up()
       .ele("vBCST").txt("0.00").up().ele("vST").txt("0.00").up().ele("vFCPST").txt("0.00").up().ele("vFCPSTRet").txt("0.00").up()
       .ele("vProd").txt(vT).up().ele("vFrete").txt("0.00").up().ele("vSeg").txt("0.00").up().ele("vDesc").txt("0.00").up()
       .ele("vII").txt("0.00").up().ele("vIPI").txt("0.00").up().ele("vIPIDevol").txt("0.00").up().ele("vPIS").txt("0.00").up()
       .ele("vCOFINS").txt("0.00").up().ele("vOutro").txt("0.00").up().ele("vNF").txt(vT);

    inf.ele("transp").ele("modFrete").txt("9");
    inf.ele("pag").ele("detPag").ele("tPag").txt(String(p.pagamento.forma_codigo || "01")).up().ele("vPag").txt(vT);

    // 4. ASSINATURA RIGOROSA
    const sig = new SignedXml();
    sig.privateKey = keyPem; sig.publicCert = certPem;
    sig.canonicalizationAlgorithm = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
    sig.signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    sig.addReference({ 
      xpath: "//*[local-name(.)='infNFe']", 
      transforms: ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"], 
      digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256" 
    });
    sig.computeSignature(xml.end({ headless: true }), { location: { reference: "//*[local-name(.)='infNFe']", action: "after" } });

    // 5. QR CODE
    const csc = p.certificado.csc || p.certificado.csc_token;
    const cscId = String(p.certificado.csc_id).padStart(6, "0");
    const hash = crypto.createHash("sha1").update(`${chave}|2|${tpAmb}|${cscId}${csc}`).digest("hex").toUpperCase();
    const urlC = tpAmb === 1 ? "https://nfe.sefaz.go.gov.br/nfeweb/sites/nfce/danfeNFCe" : "https://homolog.sefaz.go.gov.br/nfeweb/sites/nfce/danfeNFCe";
    const qrCode = `${urlC}?p=${chave}|2|${tpAmb}|${cscId}|${hash}`;

    const xmlFinal = sig.getSignedXml().replace("</NFe>", `<infNFeSupl xmlns="http://www.portalfiscal.inf.br/nfe"><qrCode><![CDATA[${qrCode}]]></qrCode><urlChave>${urlC}</urlChave></infNFeSupl></NFe>`);
    const soap = `<?xml version="1.0" encoding="utf-8"?><soap12:Envelope xmlns:soap12="http://www.w3.org/2003/05/soap-envelope"><soap12:Body><nfeDadosMsg xmlns="http://www.portalfiscal.inf.br/nfe/wsdl/NFeAutorizacao4"><enviNFe xmlns="http://www.portalfiscal.inf.br/nfe" versao="4.00"><idLote>1</idLote><indSinc>1</indSinc>${xmlFinal}</enviNFe></nfeDadosMsg></soap12:Body></soap12:Envelope>`;

    const resSefaz = await axios.post(tpAmb === 1 ? SEFAZ_GO.prod : SEFAZ_GO.homolog, soap, {
      httpsAgent: new https.Agent({ pfx: certBuffer, passphrase: String(p.certificado.senha), rejectUnauthorized: false }),
      headers: { "Content-Type": "application/soap+xml; charset=utf-8" }
    });

    const result = new XMLParser({ ignoreAttributes: false }).parse(resSefaz.data);
    const ret = result["soap:Envelope"]?.["soap:Body"]?.nfeResultMsg?.retEnviNFe || result["env:Envelope"]?.["env:Body"]?.nfeResultMsg?.retEnviNFe;
    
    console.log("CSTAT SEFAZ FINAL:", ret?.protNFe?.infProt?.cStat || ret?.cStat);
    res.json({ sefaz: ret });

  } catch (err: any) {
    res.status(500).json({ autorizado: false, motivo: err.message });
  }
});

app.listen(Number(process.env.PORT || 3000), () => console.log("🚀 Servidor Luziânia Ativo"));