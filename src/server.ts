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

// --- Helpers de Limpeza Segura ---
const clean = (v: any) => String(v ?? "").replace(/\D/g, "");
const safeNo = (v: any) => { const n = Number(v); return Number.isFinite(n) ? n : 0; };
const norm = (v: any) => String(v ?? "").trim().normalize("NFD").replace(/[\u0300-\u036f]/g, "").replace(/[<>&\"]/g, "").toUpperCase();

app.post("/nfce/emitir/:orderId", async (req, res) => {
  console.log("--- NOVA TENTATIVA NFC-E (LUZIÂNIA - ORDEM ESTRITA) ---");
  try {
    const p = req.body;
    const tpAmb = Number(p.ambiente || 2);

    // 1. Processar Certificado PFX
    const certBuffer = Buffer.from(p.certificado.pfx_base64, "base64");
    const p12 = forge.pkcs12.pkcs12FromAsn1(forge.asn1.fromDer(forge.util.createBuffer(certBuffer.toString("binary"))), String(p.certificado.senha));
    const certBag = p12.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag]![0];
    const keyBag = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag]![0];
    const certPem = forge.pki.certificateToPem(certBag.cert!);
    const keyPem = forge.pki.privateKeyToPem(keyBag.key!);

    // 2. Chave de Acesso (14 dígitos CNPJ obrigatórios)
    const cnpj = clean(p.emitente.cnpj).padStart(14, "0");
    const dh = new Date(new Date().getTime() - (3 * 60 * 60 * 1000)).toISOString().replace(/\.\d+Z$/, "-03:00");
    const cNF = String(Math.floor(Math.random() * 99999999)).padStart(8, "0");
    const serie = String(p.serie || 1).padStart(3, "0");
    const nNF = String(p.numero || 1).padStart(9, "0");
    const base43 = `52${dh.slice(2, 4)}${dh.slice(5, 7)}${cnpj}65${serie}${nNF}1${cNF}`;
    
    let soma = 0, peso = 2;
    for (let i = base43.length - 1; i >= 0; i--) { soma += Number(base43[i]) * peso; peso = peso === 9 ? 2 : peso + 1; }
    const dv = (soma % 11 === 0 || soma % 11 === 1) ? "0" : String(11 - (soma % 11));
    const chave = base43 + dv;

    // 3. Montar XML - Passo a Passo com xmlbuilder2
    const root = create({ version: "1.0", encoding: "UTF-8" }).ele("NFe", { xmlns: "http://www.portalfiscal.inf.br/nfe" });
    const infNFe = root.ele("infNFe", { versao: "4.00", Id: `NFe${chave}` });

    // Grupo IDE (Adicionado indInter obrigatório)
    const ide = infNFe.ele("ide");
    ide.ele("cUF").txt("52");
    ide.ele("cNF").txt(cNF);
    ide.ele("natOp").txt("VENDA");
    ide.ele("mod").txt("65");
    ide.ele("serie").txt(String(p.serie || 1));
    ide.ele("nNF").txt(String(p.numero || 1));
    ide.ele("dhEmi").txt(dh);
    ide.ele("tpNF").txt("1");
    ide.ele("idDest").txt("1");
    ide.ele("cMunFG").txt("5212501");
    ide.ele("tpImp").txt("4");
    ide.ele("tpEmis").txt("1");
    ide.ele("cDV").txt(dv);
    ide.ele("tpAmb").txt(String(tpAmb));
    ide.ele("finNFe").txt("1");
    ide.ele("indFinal").txt("1");
    ide.ele("indPres").txt("1"); 
    ide.ele("indInter").txt("0"); // OBRIGATÓRIO: 0 = Sem intermediador
    ide.ele("procEmi").txt("0");
    ide.ele("verProc").txt("1.0.0");

    // Grupo EMIT
    const emit = infNFe.ele("emit");
    emit.ele("CNPJ").txt(cnpj);
    emit.ele("xNome").txt(norm(p.emitente.razao_social));
    if (p.emitente.nome_fantasia) emit.ele("xFant").txt(norm(p.emitente.nome_fantasia));
    const enderEmit = emit.ele("enderEmit");
    enderEmit.ele("xLgr").txt(norm(p.emitente.logradouro));
    enderEmit.ele("nro").txt(norm(p.emitente.numero || "SN"));
    if (p.emitente.complemento) enderEmit.ele("xCpl").txt(norm(p.emitente.complemento));
    enderEmit.ele("xBairro").txt(norm(p.emitente.bairro || "CENTRO"));
    enderEmit.ele("cMun").txt("5212501");
    enderEmit.ele("xMun").txt("LUZIANIA");
    enderEmit.ele("UF").txt("GO");
    enderEmit.ele("CEP").txt(clean(p.emitente.cep));
    enderEmit.ele("cPais").txt("1058");
    enderEmit.ele("xPais").txt("BRASIL");
    emit.ele("IE").txt(clean(p.emitente.inscricao_estadual));
    emit.ele("CRT").txt("1");

    // Grupo DEST
    if (clean(p.destinatario?.cpf)) {
      const dest = infNFe.ele("dest");
      dest.ele("CPF").txt(clean(p.destinatario.cpf));
      if (p.destinatario?.nome) dest.ele("xNome").txt(norm(p.destinatario.nome));
      dest.ele("indIEDest").txt("9");
    }

    // Grupo ITENS
    p.itens.forEach((it: any, i: number) => {
      const q = safeNo(it.quantidade || 1);
      const v = safeNo(it.valor_unitario);
      const det = infNFe.ele("det", { nItem: i + 1 });
      const prod = det.ele("prod");
      prod.ele("cProd").txt(norm(it.codigo_produto || i + 1));
      prod.ele("cEAN").txt("SEM GTIN");
      prod.ele("xProd").txt(norm(it.descricao || "PRODUTO"));
      prod.ele("NCM").txt(clean(it.ncm) || "21069090");
      prod.ele("CFOP").txt(clean(it.cfop) || "5102");
      prod.ele("uCom").txt("UN");
      prod.ele("qCom").txt(q.toFixed(4));
      prod.ele("vUnCom").txt(v.toFixed(4));
      prod.ele("vProd").txt((q * v).toFixed(2));
      prod.ele("cEANTrib").txt("SEM GTIN");
      prod.ele("uTrib").txt("UN");
      prod.ele("qTrib").txt(q.toFixed(4));
      prod.ele("vUnTrib").txt(v.toFixed(4));
      prod.ele("indTot").txt("1");

      const imp = det.ele("imposto");
      const icms = imp.ele("ICMS").ele("ICMSSN102");
      icms.ele("orig").txt("0");
      icms.ele("CSOSN").txt("102");
      imp.ele("PIS").ele("PISNT").ele("CST").txt("07");
      imp.ele("COFINS").ele("COFINSNT").ele("CST").txt("07");
    });

    // Grupo TOTAL (Ordem Absoluta MOC)
    const vTotal = safeNo(p.totais.valor_total).toFixed(2);
    const tot = infNFe.ele("total").ele("ICMSTot");
    tot.ele("vBC").txt("0.00");
    tot.ele("vICMS").txt("0.00");
    tot.ele("vICMSDeson").txt("0.00");
    tot.ele("vFCP").txt("0.00");
    tot.ele("vBCST").txt("0.00");
    tot.ele("vST").txt("0.00");
    tot.ele("vFCPST").txt("0.00");
    tot.ele("vFCPSTRet").txt("0.00");
    tot.ele("vProd").txt(vTotal);
    tot.ele("vFrete").txt("0.00");
    tot.ele("vSeg").txt("0.00");
    tot.ele("vDesc").txt("0.00");
    tot.ele("vII").txt("0.00");
    tot.ele("vIPI").txt("0.00");
    tot.ele("vIPIDevol").txt("0.00");
    tot.ele("vPIS").txt("0.00");
    tot.ele("vCOFINS").txt("0.00");
    tot.ele("vOutro").txt("0.00");
    tot.ele("vNF").txt(vTotal);
    tot.ele("vTotTrib").txt("0.00");

    // Grupo TRANSP e PAG
    infNFe.ele("transp").ele("modFrete").txt("9");
    const pag = infNFe.ele("pag");
    const detPag = pag.ele("detPag");
    detPag.ele("tPag").txt(String(p.pagamento?.forma_codigo || "01").padStart(2, "0"));
    detPag.ele("vPag").txt(vTotal);

    // --- O PULO DO GATO: GERAR QR CODE AQUI ANTES DA ASSINATURA ---
    const csc = String(p.certificado.csc || p.certificado.csc_token).trim();
    const cscId = String(p.certificado.csc_id).padStart(6, "0");
    const qrConcat = `${chave}|2|${tpAmb}|${cscId}${csc}`;
    const hash = crypto.createHash("sha1").update(qrConcat).digest("hex").toUpperCase();
    const urlC = tpAmb === 1 ? SEFAZ_GO.qrProd : SEFAZ_GO.qrHomolog;
    const qrCode = `${urlC}?p=${chave}|2|${tpAmb}|${cscId}|${hash}`;

    // Adiciona o suplemento diretamente no root ANTES da assinatura
    const supl = root.ele("infNFeSupl");
    supl.ele("qrCode").dat(qrCode);
    supl.ele("urlChave").txt(urlC);

    // Converte tudo para string
    const xmlRaw = root.end({ headless: true });

    // 4. Assinatura - Ela vai automaticamente para o FINAL do XML, depois do Suplemento
    const sig = new SignedXml();
    sig.privateKey = keyPem;
    sig.publicCert = certPem;
    sig.canonicalizationAlgorithm = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
    sig.signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    sig.addReference({
      xpath: "//*[local-name(.)='infNFe']",
      transforms: [
        "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
        "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
      ],
      digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256"
    });

    // O comando 'append' garante que a tag Signature vá para o lugar certo
    sig.computeSignature(xmlRaw, {
      location: { reference: "//*[local-name(.)='NFe']", action: "append" }
    });
    
    const xmlFinal = sig.getSignedXml();

    // 5. Envelope SOAP e Envio
    const soap = `<?xml version="1.0" encoding="utf-8"?><soap12:Envelope xmlns:soap12="http://www.w3.org/2003/05/soap-envelope"><soap12:Body><nfeDadosMsg xmlns="http://www.portalfiscal.inf.br/nfe/wsdl/NFeAutorizacao4"><enviNFe xmlns="http://www.portalfiscal.inf.br/nfe" versao="4.00"><idLote>1</idLote><indSinc>1</indSinc>${xmlFinal.replace(/<\?xml[^>]*\?>/i, "")}</enviNFe></nfeDadosMsg></soap12:Body></soap12:Envelope>`;

    console.log("ENVIANDO PARA SEFAZ...");
    const resSefaz = await axios.post(tpAmb === 1 ? SEFAZ_GO.prod : SEFAZ_GO.homolog, soap, {
      httpsAgent: new https.Agent({ pfx: certBuffer, passphrase: String(p.certificado.senha), rejectUnauthorized: false }),
      headers: { "Content-Type": "application/soap+xml; charset=utf-8" },
      validateStatus: () => true
    });

    // 6. Resposta
    const result = new XMLParser({ ignoreAttributes: false }).parse(resSefaz.data);
    const ret = result["soap:Envelope"]?.["soap:Body"]?.nfeResultMsg?.retEnviNFe || result["env:Envelope"]?.["env:Body"]?.nfeResultMsg?.retEnviNFe;
    const cStat = String(ret?.protNFe?.infProt?.cStat || ret?.cStat || "0");
    
    console.log("CSTAT FINAL SEFAZ-GO:", cStat);
    res.json({ autorizado: cStat === "100", cStat: cStat, motivo: ret?.xMotivo || ret?.protNFe?.infProt?.xMotivo || "Erro", chave });

  } catch (err: any) {
    console.error("ERRO GRAVE:", err.message);
    res.status(500).json({ autorizado: false, motivo: err.message });
  }
});

app.listen(Number(process.env.PORT || 3000), () => console.log("🚀 Servidor Fiscal Luziânia Ativo"));