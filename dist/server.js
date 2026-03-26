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
const pdfkit_1 = __importDefault(require("pdfkit"));
const qrcode_1 = __importDefault(require("qrcode"));
const axios_1 = __importDefault(require("axios"));
const https_1 = __importDefault(require("https"));
const fast_xml_parser_1 = require("fast-xml-parser");
const xml_crypto_1 = require("xml-crypto");
dotenv_1.default.config();
const app = (0, express_1.default)();
app.use((0, cors_1.default)());
app.use(express_1.default.json({ limit: "30mb" }));
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
const CEP_PADRAO = "72856472";
const CIDADE_PADRAO = "LUZIANIA";
const UF_PADRAO = "GO";
const LOGRADOURO_PADRAO = "RUA MONÇÃO";
const NUMERO_PADRAO = "30";
const BAIRRO_PADRAO = "CENTRO";
const CODIGO_MUNICIPIO_PADRAO = "5212501";
function onlyNumbers(value) {
    return String(value ?? "").replace(/\D/g, "");
}
function safeNumber(value, fallback = 0) {
    const n = Number(value);
    return Number.isFinite(n) ? n : fallback;
}
function pad(value, size) {
    return String(value).padStart(size, "0");
}
function normalizarCep(value) {
    const cep = onlyNumbers(value);
    return cep.length === 8 ? cep : CEP_PADRAO;
}
function normalizeText(value, fallback = "") {
    const text = String(value ?? fallback).trim();
    return text || fallback;
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
async function obterCertificadoBuffer(payload) {
    if (payload?.certificado?.pfx_base64) {
        console.log("Usando certificado via pfx_base64");
        return Buffer.from(String(payload.certificado.pfx_base64), "base64");
    }
    throw new Error("Certificado não informado. Envie certificado.pfx_base64");
}
function extrairCertificadoEChave(buffer, senha) {
    try {
        const p12Der = node_forge_1.default.util.createBuffer(buffer.toString("binary"));
        const p12Asn1 = node_forge_1.default.asn1.fromDer(p12Der);
        const p12 = node_forge_1.default.pkcs12.pkcs12FromAsn1(p12Asn1, senha);
        const certBags = p12.getBags({ bagType: node_forge_1.default.pki.oids.certBag })[node_forge_1.default.pki.oids.certBag] || [];
        const keyBags = p12.getBags({ bagType: node_forge_1.default.pki.oids.pkcs8ShroudedKeyBag })[node_forge_1.default.pki.oids.pkcs8ShroudedKeyBag] || [];
        if (!certBags.length) {
            throw new Error("Nenhum certificado encontrado no .p12/.pfx");
        }
        if (!keyBags.length) {
            throw new Error("Nenhuma chave privada encontrada no .p12/.pfx");
        }
        const cert = certBags[0].cert;
        const key = keyBags[0].key;
        return {
            certPem: node_forge_1.default.pki.certificateToPem(cert),
            keyPem: node_forge_1.default.pki.privateKeyToPem(key),
            serialNumber: cert.serialNumber,
            validFrom: cert.validity.notBefore,
            validTo: cert.validity.notAfter,
        };
    }
    catch (error) {
        throw new Error(`Erro ao ler certificado A1: ${error.message}`);
    }
}
function validarCertificadoP12(buffer, senha) {
    const data = extrairCertificadoEChave(buffer, senha);
    return {
        serialNumber: data.serialNumber,
        validFrom: data.validFrom,
        validTo: data.validTo,
    };
}
function gerarChave(payload, cNF, dhEmi) {
    const cUF = "52";
    const aamm = dhEmi.slice(2, 7).replace("-", "");
    const cnpj = onlyNumbers(payload.emitente?.cnpj);
    const mod = String(payload.modelo || 65);
    const serie = pad(payload.serie || 1, 3);
    const numero = pad(payload.numero || 1, 9);
    const tpEmis = "1";
    const base43 = `${cUF}${aamm}${cnpj.padStart(14, "0")}${mod}${serie}${numero}${tpEmis}${cNF}`;
    const dv = calcularDVChave(base43);
    return `${base43}${dv}`;
}
function gerarXmlBase(payload) {
    const tpAmb = String(payload.ambiente || 2);
    const dhEmiDate = payload?.data_emissao ? new Date(payload.data_emissao) : new Date();
    const dhEmi = dhEmiDate.toISOString();
    const cNF = String(Math.floor(Math.random() * 99999999)).padStart(8, "0");
    const mod = String(payload.modelo || 65);
    const serie = String(payload.serie || 1);
    const numero = String(payload.numero || 1);
    const cnpj = onlyNumbers(payload.emitente?.cnpj);
    const cMun = String(payload.emitente?.codigo_municipio || CODIGO_MUNICIPIO_PADRAO);
    const chave = gerarChave(payload, cNF, dhEmi);
    const dv = chave.slice(-1);
    const cep = normalizarCep(payload.emitente?.cep);
    const ie = onlyNumbers(payload.emitente?.inscricao_estadual || "");
    const fone = onlyNumbers(payload.emitente?.fone || "");
    const logradouro = normalizeText(payload.emitente?.logradouro, LOGRADOURO_PADRAO);
    const numeroEndereco = normalizeText(payload.emitente?.numero, NUMERO_PADRAO);
    const bairro = normalizeText(payload.emitente?.bairro, BAIRRO_PADRAO);
    const cidade = CIDADE_PADRAO;
    const uf = UF_PADRAO;
    const razaoSocial = normalizeText(payload.emitente?.razao_social || payload.emitente?.nome_fantasia, "");
    const naturezaOperacao = normalizeText(payload.natureza_operacao, "VENDA");
    if (!cnpj)
        throw new Error("emitente.cnpj é obrigatório");
    if (!ie)
        throw new Error("emitente.inscricao_estadual é obrigatória");
    if (!razaoSocial)
        throw new Error("emitente.razao_social é obrigatória");
    const valorProdutos = payload?.totais?.valor_produtos != null
        ? safeNumber(payload.totais.valor_produtos, 0)
        : (payload.itens || []).reduce((soma, item) => soma + safeNumber(item.valor_total, 0), 0);
    const valorTotal = safeNumber(payload?.totais?.valor_total, valorProdutos);
    const valorFrete = payload?.totais?.valor_frete != null
        ? safeNumber(payload.totais.valor_frete, 0)
        : Math.max(0, Number((valorTotal - valorProdutos).toFixed(2)));
    const root = (0, xmlbuilder2_1.create)({ version: "1.0", encoding: "UTF-8" }).ele("NFe");
    const infNFe = root.ele("infNFe", {
        xmlns: "http://www.portalfiscal.inf.br/nfe",
        versao: "4.00",
        Id: `NFe${chave}`,
    });
    const ide = infNFe.ele("ide");
    ide.ele("cUF").txt("52");
    ide.ele("cNF").txt(cNF);
    ide.ele("natOp").txt(naturezaOperacao);
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
    emit.ele("xNome").txt(razaoSocial);
    if (payload.emitente?.nome_fantasia) {
        emit.ele("xFant").txt(normalizeText(payload.emitente.nome_fantasia));
    }
    const enderEmit = emit.ele("enderEmit");
    enderEmit.ele("xLgr").txt(logradouro);
    enderEmit.ele("nro").txt(numeroEndereco);
    if (payload.emitente?.complemento) {
        enderEmit.ele("xCpl").txt(normalizeText(payload.emitente.complemento));
    }
    enderEmit.ele("xBairro").txt(bairro);
    enderEmit.ele("cMun").txt(cMun);
    enderEmit.ele("xMun").txt(cidade);
    enderEmit.ele("UF").txt(uf);
    enderEmit.ele("CEP").txt(cep);
    enderEmit.ele("cPais").txt("1058");
    enderEmit.ele("xPais").txt("BRASIL");
    if (fone) {
        enderEmit.ele("fone").txt(fone);
    }
    emit.ele("IE").txt(ie);
    emit.ele("CRT").txt(payload.emitente?.regime_tributario === "simples_nacional" ? "1" : "3");
    const cpfDest = onlyNumbers(payload?.destinatario?.cpf);
    if (cpfDest) {
        const dest = infNFe.ele("dest");
        dest.ele("CPF").txt(cpfDest);
        if (payload.destinatario?.nome) {
            dest.ele("xNome").txt(normalizeText(payload.destinatario.nome));
        }
        dest.ele("indIEDest").txt("9");
    }
    for (const item of payload.itens || []) {
        const quantidade = safeNumber(item.quantidade, 1);
        const valorUnitario = safeNumber(item.valor_unitario, 0);
        const valorItem = item.valor_total != null
            ? safeNumber(item.valor_total, valorUnitario * quantidade)
            : valorUnitario * quantidade;
        const det = infNFe.ele("det", { nItem: String(item.numero_item || 1) });
        const prod = det.ele("prod");
        prod.ele("cProd").txt(String(item.codigo_produto || item.numero_item || "1"));
        prod.ele("cEAN").txt("SEM GTIN");
        prod.ele("xProd").txt(normalizeText(item.descricao, "ITEM"));
        prod.ele("NCM").txt(normalizeText(item.ncm, "21069090"));
        prod.ele("CFOP").txt(normalizeText(item.cfop, "5102"));
        prod.ele("uCom").txt(normalizeText(item.unidade, "UN"));
        prod.ele("qCom").txt(quantidade.toFixed(4));
        prod.ele("vUnCom").txt(valorUnitario.toFixed(2));
        prod.ele("vProd").txt(valorItem.toFixed(2));
        prod.ele("cEANTrib").txt("SEM GTIN");
        prod.ele("uTrib").txt(normalizeText(item.unidade, "UN"));
        prod.ele("qTrib").txt(quantidade.toFixed(4));
        prod.ele("vUnTrib").txt(valorUnitario.toFixed(2));
        prod.ele("indTot").txt("1");
        const imposto = det.ele("imposto");
        imposto.ele("vTotTrib").txt("0.00");
        const icms = imposto.ele("ICMS");
        const icmssn102 = icms.ele("ICMSSN102");
        icmssn102.ele("orig").txt(String(item?.impostos?.icms?.origem ?? "0"));
        icmssn102.ele("CSOSN").txt(String(item?.impostos?.icms?.csosn ?? "102"));
        const pis = imposto.ele("PIS");
        const pisnt = pis.ele("PISNT");
        pisnt.ele("CST").txt(String(item?.impostos?.pis?.cst ?? "07"));
        const cofins = imposto.ele("COFINS");
        const cofinsnt = cofins.ele("COFINSNT");
        cofinsnt.ele("CST").txt(String(item?.impostos?.cofins?.cst ?? "07"));
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
    total.ele("vProd").txt(valorProdutos.toFixed(2));
    total.ele("vFrete").txt(valorFrete.toFixed(2));
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
    const transp = infNFe.ele("transp");
    transp.ele("modFrete").txt("9");
    const pag = infNFe.ele("pag");
    const detPag = pag.ele("detPag");
    detPag.ele("tPag").txt(String(payload.pagamento?.forma_codigo || "01"));
    detPag.ele("vPag").txt(safeNumber(payload.pagamento?.valor, valorTotal).toFixed(2));
    const troco = safeNumber(payload.pagamento?.troco, 0);
    if (troco > 0) {
        pag.ele("vTroco").txt(troco.toFixed(2));
    }
    const infAdic = infNFe.ele("infAdic");
    infAdic.ele("infCpl").txt(tpAmb === "2"
        ? "EMITIDA EM AMBIENTE DE HOMOLOGACAO - SEM VALOR FISCAL"
        : normalizeText(payload.informacoes_complementares, ""));
    return {
        xml: root.end({ headless: true, prettyPrint: false }),
        chave,
    };
}
function assinarXmlNfce(xml, certPem, keyPem) {
    const xmlLimpo = xml.replace(/<\?xml[^>]*\?>/i, "").trim();
    const sig = new xml_crypto_1.SignedXml();
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
    return sig.getSignedXml().replace(/<\?xml[^>]*\?>/i, "").trim();
}
function extrairApenasNFe(xmlAssinado) {
    const xmlSemDeclaracao = xmlAssinado.replace(/<\?xml[^>]*\?>/i, "").trim();
    const match = xmlSemDeclaracao.match(/<NFe[\s\S]*<\/NFe>/);
    if (!match) {
        console.error("XML ASSINADO COMPLETO:");
        console.log(xmlAssinado);
        throw new Error("Não encontrou <NFe> no XML assinado");
    }
    return match[0]
        .replace(/<NFe xmlns="http:\/\/www\.portalfiscal\.inf\.br\/nfe">/, "<NFe>")
        .trim();
}
function montarSoapAutorizacao(xmlAssinado) {
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
async function enviarParaSefazGo(xmlAssinado, ambiente, certBuffer, senha) {
    const url = ambiente === 1
        ? SEFAZ_GO.autorizacaoProducao
        : SEFAZ_GO.autorizacaoHomologacao;
    const soapBody = montarSoapAutorizacao(xmlAssinado);
    console.log("========== XML ENVIADO SEFAZ ==========");
    console.log(soapBody);
    console.log("========== FIM XML ENVIADO ==========");
    const httpsAgent = new https_1.default.Agent({
        pfx: certBuffer,
        passphrase: senha,
        rejectUnauthorized: false,
        minVersion: "TLSv1.2",
        keepAlive: false,
    });
    const response = await axios_1.default.post(url, soapBody, {
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
        throw new Error(`SEFAZ retornou HTTP ${response.status}: ${typeof response.data === "string" ? response.data : JSON.stringify(response.data)}`);
    }
    return typeof response.data === "string" ? response.data : JSON.stringify(response.data);
}
function extrairAutorizacao(xmlRetorno) {
    const parser = new fast_xml_parser_1.XMLParser({
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
async function gerarDanfeBase64(payload, numero, chaveAcesso) {
    const doc = new pdfkit_1.default({ margin: 20, size: "A4" });
    const buffers = [];
    doc.on("data", (chunk) => buffers.push(chunk));
    const done = new Promise((resolve) => {
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
        doc.text(`${item.numero_item}. ${item.descricao} | Qtd: ${safeNumber(item.quantidade, 1)} | Unit: ${safeNumber(item.valor_unitario, 0).toFixed(2)} | Total: ${safeNumber(item.valor_total, 0).toFixed(2)}`);
    }
    doc.moveDown();
    doc.text(`Valor total: ${safeNumber(payload.totais?.valor_total, 0).toFixed(2)}`);
    const qrData = `CHAVE=${chaveAcesso}`;
    const qrDataUrl = await qrcode_1.default.toDataURL(qrData);
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
        console.log("📦 ORDER ID:", req.params.orderId);
        console.log("📦 PAYLOAD RECEBIDO:");
        console.log(JSON.stringify(req.body, null, 2));
        const orderId = req.params.orderId;
        const payload = req.body;
        if (!orderId) {
            return res.status(400).json({
                autorizado: false,
                status: "ERROR",
                motivo: "orderId não informado",
            });
        }
        const camposFaltando = [];
        if (!payload?.emitente?.cnpj)
            camposFaltando.push("emitente.cnpj");
        if (!payload?.emitente?.razao_social && !payload?.emitente?.nome_fantasia) {
            camposFaltando.push("emitente.razao_social");
        }
        if (!payload?.emitente?.inscricao_estadual) {
            camposFaltando.push("emitente.inscricao_estadual");
        }
        if (!payload?.certificado?.senha)
            camposFaltando.push("certificado.senha");
        if (!payload?.certificado?.pfx_base64)
            camposFaltando.push("certificado.pfx_base64");
        if (!Array.isArray(payload?.itens) || payload.itens.length === 0)
            camposFaltando.push("itens");
        if (payload?.totais?.valor_total == null)
            camposFaltando.push("totais.valor_total");
        if (!payload?.pagamento?.forma_codigo)
            camposFaltando.push("pagamento.forma_codigo");
        if (payload?.pagamento?.valor == null)
            camposFaltando.push("pagamento.valor");
        if (camposFaltando.length > 0) {
            console.log("❌ CAMPOS FALTANDO:", camposFaltando);
            return res.status(400).json({
                autorizado: false,
                status: "ERROR",
                motivo: "Payload fiscal incompleto",
                campos_faltando: camposFaltando,
            });
        }
        const certBuffer = await obterCertificadoBuffer(payload);
        const certInfo = extrairCertificadoEChave(certBuffer, String(payload.certificado.senha));
        validarCertificadoP12(certBuffer, String(payload.certificado.senha));
        const { xml, chave } = gerarXmlBase(payload);
        const xmlAssinado = assinarXmlNfce(xml, certInfo.certPem, certInfo.keyPem);
        const xmlRetorno = await enviarParaSefazGo(xmlAssinado, Number(payload.ambiente || 2), certBuffer, String(payload.certificado.senha));
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
    }
    catch (err) {
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
