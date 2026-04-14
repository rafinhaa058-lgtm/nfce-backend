"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const cors_1 = __importDefault(require("cors"));
const dotenv_1 = __importDefault(require("dotenv"));
const node_forge_1 = __importDefault(require("node-forge"));
const xmlbuilder2_1 = require("xmlbuilder2");
const axios_1 = __importDefault(require("axios"));
const https_1 = __importDefault(require("https"));
const crypto_1 = __importDefault(require("crypto")); // Necessário para o Hash do QR Code
const fast_xml_parser_1 = require("fast-xml-parser");
const xml_crypto_1 = require("xml-crypto");
dotenv_1.default.config();
const app = (0, express_1.default)();
app.use((0, cors_1.default)());
app.use(express_1.default.json({ limit: "30mb" }));
// Middleware para validar JSON
app.use((err, _req, res, next) => {
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
// Configurações Padrão (Luziânia-GO)
const CEP_PADRAO = "72856472";
const CIDADE_PADRAO = "LUZIANIA";
const UF_PADRAO = "GO";
const LOGRADOURO_PADRAO = "RUA MONCAO"; // Sem acento
const NUMERO_PADRAO = "30";
const BAIRRO_PADRAO = "CENTRO";
const CODIGO_MUNICIPIO_PADRAO = "5212501"; // Luziânia-GO
// --- FUNÇÕES AUXILIARES ---
function onlyNumbers(value) {
    return String(value ?? "").replace(/\D/g, "");
}
function safeNumber(value, fallback = 0) {
    const n = Number(value);
    return Number.isFinite(n) ? n : fallback;
}
/** * Limpa o texto: Remove acentos e caracteres especiais para evitar Erro 225
 */
function normalizeText(value, fallback = "") {
    let text = String(value ?? fallback).trim();
    text = text.normalize("NFD").replace(/[\u0300-\u036f]/g, ""); // Remove acentos
    text = text.replace(/[<&"'>]/g, ""); // Remove caracteres XML proibidos
    return text.toUpperCase() || fallback;
}
function pad(value, size) {
    return String(value).padStart(size, "0");
}
function normalizarCep(value) {
    const cep = onlyNumbers(value);
    return cep.length === 8 ? cep : CEP_PADRAO;
}
function formatarDataSefaz(data) {
    const base = data ? new Date(data) : new Date();
    const local = new Date(base.getTime() - 3 * 60 * 60 * 1000); // Fuso Brasília
    const yyyy = local.getUTCFullYear();
    const mm = String(local.getUTCMonth() + 1).padStart(2, "0");
    const dd = String(local.getUTCDate()).padStart(2, "0");
    const hh = String(local.getUTCHours()).padStart(2, "0");
    const mi = String(local.getUTCMinutes()).padStart(2, "0");
    const ss = String(local.getUTCSeconds()).padStart(2, "0");
    return `${yyyy}-${mm}-${dd}T${hh}:${mi}:${ss}-03:00`;
}
function calcularDVChave(chave43) {
    let peso = 2;
    let soma = 0;
    for (let i = chave43.length - 1; i >= 0; i--) {
        soma += Number(chave43[i]) * peso;
        peso = peso === 9 ? 2 : peso + 1;
    }
    const mod = soma % 11;
    return mod === 0 || mod === 1 ? "0" : String(11 - mod);
}
// --- LOGICA DE QR CODE NFC-E ---
function gerarQrCodeNfce(chave, ambiente, cscId, csc) {
    const urlConsulta = ambiente === 1
        ? "https://nfe.sefaz.go.gov.br/nfeweb/sites/nfce/danfeNFCe"
        : "https://homolog.sefaz.go.gov.br/nfeweb/sites/nfce/danfeNFCe";
    // Formato: chave|versao|tpAmb|cIdToken + CSC
    const cIdToken = pad(cscId, 6);
    const paramParaHash = `${chave}|2|${ambiente}|${cIdToken}${csc}`;
    const hash = crypto_1.default.createHash("sha1").update(paramParaHash).digest("hex").toUpperCase();
    return `${urlConsulta}?p=${chave}|2|${ambiente}|${cIdToken}|${hash}`;
}
// --- PROCESSAMENTO DO CERTIFICADO ---
async function obterCertificadoBuffer(payload) {
    if (payload?.certificado?.pfx_base64) {
        return Buffer.from(String(payload.certificado.pfx_base64), "base64");
    }
    throw new Error("Certificado PFX (base64) não informado.");
}
function extrairCertificadoEChave(buffer, senha) {
    try {
        const p12Der = node_forge_1.default.util.createBuffer(buffer.toString("binary"));
        const p12Asn1 = node_forge_1.default.asn1.fromDer(p12Der);
        const p12 = node_forge_1.default.pkcs12.pkcs12FromAsn1(p12Asn1, senha);
        const certBags = p12.getBags({ bagType: node_forge_1.default.pki.oids.certBag })[node_forge_1.default.pki.oids.certBag] || [];
        const keyBags = p12.getBags({ bagType: node_forge_1.default.pki.oids.pkcs8ShroudedKeyBag })[node_forge_1.default.pki.oids.pkcs8ShroudedKeyBag] || [];
        if (!certBags.length || !keyBags.length)
            throw new Error("Certificado ou Chave não encontrados no PFX.");
        const cert = certBags[0].cert;
        const key = keyBags[0].key;
        return {
            certPem: node_forge_1.default.pki.certificateToPem(cert),
            keyPem: node_forge_1.default.pki.privateKeyToPem(key),
        };
    }
    catch (error) {
        throw new Error(`Erro no Certificado: ${error.message}`);
    }
}
// --- GERAÇÃO DO XML ---
function gerarXmlBase(payload) {
    const tpAmb = String(payload.ambiente || 2);
    const dhEmi = formatarDataSefaz(payload?.data_emissao);
    const cNF = pad(Math.floor(Math.random() * 99999999), 8);
    const mod = "65"; // Sempre 65 para NFC-e (Delivery)
    const serie = String(payload.serie || 1);
    const numero = String(payload.numero || 1);
    const cnpj = onlyNumbers(payload.emitente?.cnpj);
    const cMun = String(payload.emitente?.codigo_municipio || CODIGO_MUNICIPIO_PADRAO);
    // Gerar Chave
    const aamm = dhEmi.slice(2, 7).replace("-", "");
    const base43 = `52${aamm}${cnpj.padStart(14, "0")}65${pad(serie, 3)}${pad(numero, 9)}1${cNF}`;
    const dv = calcularDVChave(base43);
    const chave = `${base43}${dv}`;
    const itens = Array.isArray(payload.itens) ? payload.itens : [];
    const valorProdutos = safeNumber(payload.totais?.valor_produtos || itens.reduce((s, i) => s + (safeNumber(i.valor_unitario) * safeNumber(i.quantidade)), 0));
    const valorTotal = valorProdutos;
    const root = (0, xmlbuilder2_1.create)({ version: "1.0", encoding: "UTF-8" }).ele("NFe", { xmlns: "http://www.portalfiscal.inf.br/nfe" });
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
    ide.ele("tpImp").txt("4"); // DANFE NFC-e
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
    emit.ele("xNome").txt(normalizeText(payload.emitente?.razao_social));
    if (payload.emitente?.nome_fantasia)
        emit.ele("xFant").txt(normalizeText(payload.emitente.nome_fantasia));
    const enderEmit = emit.ele("enderEmit");
    enderEmit.ele("xLgr").txt(normalizeText(payload.emitente?.logradouro, LOGRADOURO_PADRAO));
    enderEmit.ele("nro").txt(normalizeText(payload.emitente?.numero, NUMERO_PADRAO));
    enderEmit.ele("xBairro").txt(normalizeText(payload.emitente?.bairro, BAIRRO_PADRAO));
    enderEmit.ele("cMun").txt(cMun);
    enderEmit.ele("xMun").txt(CIDADE_PADRAO);
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
    itens.forEach((item, index) => {
        const q = safeNumber(item.quantidade, 1);
        const v = safeNumber(item.valor_unitario, 0);
        const det = infNFe.ele("det", { nItem: String(index + 1) });
        const prod = det.ele("prod");
        prod.ele("cProd").txt(String(item.codigo_produto || index + 1));
        prod.ele("cEAN").txt("SEM GTIN");
        prod.ele("xProd").txt(normalizeText(item.descricao, "PRODUTO"));
        prod.ele("NCM").txt(normalizeText(item.ncm, "21069090"));
        prod.ele("CFOP").txt(normalizeText(item.cfop, "5102"));
        prod.ele("uCom").txt(normalizeText(item.unidade, "UN"));
        prod.ele("qCom").txt(q.toFixed(4));
        prod.ele("vUnCom").txt(v.toFixed(2));
        prod.ele("vProd").txt((q * v).toFixed(2));
        prod.ele("cEANTrib").txt("SEM GTIN");
        prod.ele("uTrib").txt(normalizeText(item.unidade, "UN"));
        prod.ele("qTrib").txt(q.toFixed(4));
        prod.ele("vUnTrib").txt(v.toFixed(2));
        prod.ele("indTot").txt("1");
        const imposto = det.ele("imposto");
        const icms = imposto.ele("ICMS").ele("ICMSSN102");
        icms.ele("orig").txt("0");
        icms.ele("CSOSN").txt("102");
        imposto.ele("PIS").ele("PISNT").ele("CST").txt("07");
        imposto.ele("COFINS").ele("COFINSNT").ele("CST").txt("07");
    });
    const total = infNFe.ele("total").ele("ICMSTot");
    ["vBC", "vICMS", "vICMSDeson", "vFCP", "vBCST", "vST", "vFCPST", "vFCPSTRet"].forEach(f => total.ele(f).txt("0.00"));
    total.ele("vProd").txt(valorProdutos.toFixed(2));
    total.ele("vFrete").txt("0.00");
    total.ele("vSeg").txt("0.00");
    total.ele("vDesc").txt("0.00");
    total.ele("vII").txt("0.00");
    total.ele("vIPI").txt("0.00");
    total.ele("vIPIDevol").txt("0.00");
    total.ele("vPIS").txt("0.00");
    total.ele("vCOFINS").txt("0.00");
    total.ele("vOutro").txt("0.00");
    total.ele("vNF").txt(valorTotal.toFixed(2));
    total.ele("vTotTrib").txt("0.00");
    infNFe.ele("transp").ele("modFrete").txt("9");
    const pag = infNFe.ele("pag");
    const detPag = pag.ele("detPag");
    detPag.ele("tPag").txt(String(payload.pagamento?.forma_codigo || "01"));
    detPag.ele("vPag").txt(valorTotal.toFixed(2));
    return { xml: root.end({ headless: true }), chave };
}
// --- ASSINATURA E COMUNICAÇÃO ---
function assinarXmlNfce(xml, certPem, keyPem) {
    const sig = new xml_crypto_1.SignedXml();
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
// --- ENDPOINT PRINCIPAL ---
app.post("/nfce/emitir/:orderId", async (req, res) => {
    try {
        const payload = req.body;
        const tpAmb = Number(payload.ambiente || 2);
        // 1. Preparar Certificado
        const certBuffer = await obterCertificadoBuffer(payload);
        const certInfo = extrairCertificadoEChave(certBuffer, String(payload.certificado.senha));
        // 2. Gerar XML Base e Chave
        const { xml, chave } = gerarXmlBase(payload);
        // 3. Assinar XML
        const xmlAssinado = assinarXmlNfce(xml, certInfo.certPem, certInfo.keyPem);
        // 4. Adicionar QR Code (Obrigatório para NFC-e - Corrige Erro 225)
        const csc = payload.certificado.csc || payload.certificado.csc_token; // Pega do novo campo do Lovable
        const cscId = payload.certificado.csc_id;
        if (!csc || !cscId)
            throw new Error("CSC ID ou Token não informados na Config. Fiscal.");
        const urlQrCode = gerarQrCodeNfce(chave, tpAmb, cscId, csc);
        const urlConsulta = tpAmb === 1
            ? "https://nfe.sefaz.go.gov.br/nfeweb/sites/nfce/danfeNFCe"
            : "https://homolog.sefaz.go.gov.br/nfeweb/sites/nfce/danfeNFCe";
        const suplemento = `
      <infNFeSupl xmlns="http://www.portalfiscal.inf.br/nfe">
        <qrCode><![CDATA[${urlQrCode}]]></qrCode>
        <urlChave>${urlConsulta}</urlChave>
      </infNFeSupl>`;
        const xmlFinal = xmlAssinado.replace("</NFe>", `${suplemento}</NFe>`);
        // 5. Montar Envelope SOAP
        const soapBody = `<?xml version="1.0" encoding="utf-8"?>
      <soap12:Envelope xmlns:soap12="http://www.w3.org/2003/05/soap-envelope">
        <soap12:Body>
          <nfeDadosMsg xmlns="http://www.portalfiscal.inf.br/nfe/wsdl/NFeAutorizacao4">
            <enviNFe xmlns="http://www.portalfiscal.inf.br/nfe" versao="4.00">
              <idLote>1</idLote><indSinc>1</indSinc>${xmlFinal.replace(/<\?xml[^>]*\?>/i, "")}
            </enviNFe>
          </nfeDadosMsg>
        </soap12:Body>
      </soap12:Envelope>`;
        // 6. Enviar para SEFAZ-GO
        const urlSefaz = tpAmb === 1 ? SEFAZ_GO.autorizacaoProducao : SEFAZ_GO.autorizacaoHomologacao;
        const agent = new https_1.default.Agent({ pfx: certBuffer, passphrase: String(payload.certificado.senha), rejectUnauthorized: false });
        const response = await axios_1.default.post(urlSefaz, soapBody, {
            httpsAgent: agent,
            headers: { "Content-Type": "application/soap+xml; charset=utf-8" },
            timeout: 30000,
        });
        // 7. Processar Resposta
        const parser = new fast_xml_parser_1.XMLParser({ ignoreAttributes: false });
        const parsed = parser.parse(response.data);
        const retEnviNFe = parsed["soap:Envelope"]?.["soap:Body"]?.nfeResultMsg?.retEnviNFe || parsed["env:Envelope"]?.["env:Body"]?.nfeResultMsg?.retEnviNFe;
        return res.json({
            autorizado: retEnviNFe?.cStat === "100" || retEnviNFe?.protNFe?.infProt?.cStat === "100",
            status: retEnviNFe?.xMotivo || "Resposta recebida",
            sefaz_debug: retEnviNFe,
            chave_acesso: chave
        });
    }
    catch (err) {
        console.error("Erro:", err.message);
        return res.status(500).json({ autorizado: false, motivo: err.message });
    }
});
app.listen(PORT, () => console.log(`🚀 Servidor Fiscal em Luziânia rodando na porta ${PORT}`));
