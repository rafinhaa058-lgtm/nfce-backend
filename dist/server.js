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
const fast_xml_parser_1 = require("fast-xml-parser");
const xml_crypto_1 = require("xml-crypto");
dotenv_1.default.config();
const app = (0, express_1.default)();
app.use((0, cors_1.default)());
app.use(express_1.default.json({ limit: "50mb" }));
const PORT = Number(process.env.PORT || 3000);
// ===============================
// CONFIG SEFAZ GO
// ===============================
const SEFAZ = {
    PROD: "https://nfe.sefaz.go.gov.br/nfe/services/NFeAutorizacao4",
    HOMO: "https://homolog.sefaz.go.gov.br/nfe/services/NFeAutorizacao4",
};
// ===============================
// HELPERS
// ===============================
const onlyNumbers = (v) => String(v || "").replace(/\D/g, "");
const pad = (v, n) => String(v).padStart(n, "0");
function calcDV(chave43) {
    let peso = 2, soma = 0;
    for (let i = chave43.length - 1; i >= 0; i--) {
        soma += Number(chave43[i]) * peso;
        peso = peso === 9 ? 2 : peso + 1;
    }
    const mod = soma % 11;
    return mod < 2 ? "0" : String(11 - mod);
}
// ===============================
// CHAVE NFC-e
// ===============================
function gerarChave(payload, cNF) {
    const cUF = "52";
    const aamm = new Date().toISOString().slice(2, 7).replace("-", "");
    const cnpj = onlyNumbers(payload.emitente.cnpj);
    const mod = "65";
    const serie = pad(payload.serie || 1, 3);
    const numero = pad(payload.numero || 1, 9);
    const base = `${cUF}${aamm}${cnpj}${mod}${serie}${numero}1${cNF}`;
    return base + calcDV(base);
}
// ===============================
// XML COMPLETO
// ===============================
function gerarXML(payload) {
    const cNF = pad(Math.floor(Math.random() * 99999999), 8);
    const chave = gerarChave(payload, cNF);
    const xml = (0, xmlbuilder2_1.create)({ version: "1.0" })
        .ele("NFe", { xmlns: "http://www.portalfiscal.inf.br/nfe" })
        .ele("infNFe", { Id: "NFe" + chave, versao: "4.00" })
        .ele("ide")
        .ele("cUF").txt("52").up()
        .ele("cNF").txt(cNF).up()
        .ele("natOp").txt("VENDA").up()
        .ele("mod").txt("65").up()
        .ele("serie").txt(String(payload.serie || 1)).up()
        .ele("nNF").txt(String(payload.numero || 1)).up()
        .ele("tpAmb").txt(String(payload.ambiente || 2)).up()
        .ele("tpEmis").txt("1").up()
        .up()
        .ele("emit")
        .ele("CNPJ").txt(onlyNumbers(payload.emitente.cnpj)).up()
        .ele("xNome").txt(payload.emitente.razao_social).up()
        .ele("IE").txt(onlyNumbers(payload.emitente.inscricao_estadual)).up()
        .up()
        .ele("total")
        .ele("ICMSTot")
        .ele("vNF").txt(String(payload.totais.valor_total || 0)).up()
        .up()
        .up()
        .up()
        .up()
        .end({ prettyPrint: false });
    return { xml, chave };
}
// ===============================
// ASSINATURA DIGITAL
// ===============================
function assinarXML(xml, certPem, keyPem) {
    const sig = new xml_crypto_1.SignedXml();
    sig.privateKey = keyPem;
    sig.publicCert = certPem;
    sig.addReference({
        xpath: "//*[local-name()='infNFe']",
        transforms: ["http://www.w3.org/2000/09/xmldsig#enveloped-signature"],
        digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256"
    });
    sig.computeSignature(xml);
    return sig.getSignedXml();
}
// ===============================
// ENVIO SEFAZ
// ===============================
async function enviarSefaz(xml, ambiente, certBuffer, senha) {
    const url = ambiente === 1 ? SEFAZ.PROD : SEFAZ.HOMO;
    const httpsAgent = new https_1.default.Agent({
        pfx: certBuffer,
        passphrase: senha,
        rejectUnauthorized: false
    });
    const soap = `<?xml version="1.0"?>
  <soap12:Envelope xmlns:soap12="http://www.w3.org/2003/05/soap-envelope">
    <soap12:Body>
      <nfeDadosMsg xmlns="http://www.portalfiscal.inf.br/nfe/wsdl/NFeAutorizacao4">
        ${xml}
      </nfeDadosMsg>
    </soap12:Body>
  </soap12:Envelope>`;
    const res = await axios_1.default.post(url, soap, {
        httpsAgent,
        headers: { "Content-Type": "application/soap+xml" }
    });
    return res.data;
}
// ===============================
// ROTA EMISSÃO
// ===============================
app.post("/nfce/emitir/:id", async (req, res) => {
    try {
        const payload = req.body;
        const certBuffer = Buffer.from(payload.certificado.pfx_base64, "base64");
        const p12 = node_forge_1.default.pkcs12.pkcs12FromAsn1(node_forge_1.default.asn1.fromDer(node_forge_1.default.util.createBuffer(certBuffer.toString("binary"))), payload.certificado.senha);
        const cert = node_forge_1.default.pki.certificateToPem(p12.getBags({ bagType: node_forge_1.default.pki.oids.certBag })[node_forge_1.default.pki.oids.certBag][0].cert);
        const key = node_forge_1.default.pki.privateKeyToPem(p12.getBags({ bagType: node_forge_1.default.pki.oids.pkcs8ShroudedKeyBag })[node_forge_1.default.pki.oids.pkcs8ShroudedKeyBag][0].key);
        const { xml, chave } = gerarXML(payload);
        const xmlAssinado = assinarXML(xml, cert, key);
        const retorno = await enviarSefaz(xmlAssinado, payload.ambiente || 2, certBuffer, payload.certificado.senha);
        const parser = new fast_xml_parser_1.XMLParser();
        const json = parser.parse(retorno);
        return res.json({
            sucesso: true,
            chave,
            resposta: json
        });
    }
    catch (e) {
        return res.status(500).json({
            sucesso: false,
            erro: e.message
        });
    }
});
// ===============================
// HEALTH
// ===============================
app.get("/", (req, res) => {
    res.send("NFCe Profissional rodando 🚀");
});
app.listen(PORT, () => {
    console.log("🔥 NFCe Server rodando na porta " + PORT);
});
