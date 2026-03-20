import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { createClient } from "@supabase/supabase-js";
import forge from "node-forge";
import { create } from "xmlbuilder2";
import PDFDocument from "pdfkit";
import QRCode from "qrcode";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json({ limit: "20mb" }));

const PORT = Number(process.env.PORT || 3000);

const SUPABASE_URL = process.env.SUPABASE_URL as string;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY as string;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
  throw new Error("SUPABASE_URL e SUPABASE_SERVICE_ROLE_KEY são obrigatórios");
}

const supabase = createClient(
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY,
  {
    global: {
      headers: {
        Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`
      }
    }
  }
);

const XML_BUCKET = process.env.SUPABASE_XML_BUCKET || "fiscal-xml";
const DANFE_BUCKET = process.env.SUPABASE_DANFE_BUCKET || "fiscal-danfe";
const CERT_BUCKET = process.env.SUPABASE_CERT_BUCKET || "fiscal-certificados";
const STORAGE_API_URL =
  process.env.SUPABASE_STORAGE_URL || `${SUPABASE_URL}/storage/v1`;

function onlyNumbers(value: unknown) {
  return String(value || "").replace(/\D/g, "");
}

function safeNumber(value: unknown, fallback = 0) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

async function baixarCertificado(path: string) {
  const { data, error } = await supabase.storage.from(CERT_BUCKET).download(path);

  if (error || !data) {
    throw new Error(`Erro ao baixar certificado: ${error?.message || "arquivo não encontrado"}`);
  }

  return Buffer.from(await data.arrayBuffer());
}

async function obterCertificadoBuffer(payload: any) {
  if (payload?.certificado?.pfx_base64) {
    console.log("Usando certificado via pfx_base64");
    return Buffer.from(payload.certificado.pfx_base64, "base64");
  }

  if (payload?.certificado?.path) {
    console.log(`Baixando certificado do bucket: ${CERT_BUCKET}/${payload.certificado.path}`);
    return await baixarCertificado(payload.certificado.path);
  }

  throw new Error("Certificado não informado. Envie certificado.pfx_base64 ou certificado.path");
}

function validarCertificadoP12(buffer: Buffer, senha: string) {
  const p12Der = forge.util.createBuffer(buffer.toString("binary"));
  const p12Asn1 = forge.asn1.fromDer(p12Der);
  const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, senha);

  const bags = p12.getBags({ bagType: forge.pki.oids.certBag });
  const certBags = bags[forge.pki.oids.certBag] || [];

  if (!certBags.length) {
    throw new Error("Nenhum certificado encontrado no arquivo .p12/.pfx");
  }

  const cert = certBags[0].cert;

  return {
    serialNumber: cert.serialNumber,
    validFrom: cert.validity.notBefore,
    validTo: cert.validity.notAfter
  };
}

function gerarXmlBase(payload: any) {
  const cUF = "52";
  const tpAmb = String(payload.ambiente || 2);
  const dhEmi = new Date().toISOString();
  const cNF = String(Math.floor(Math.random() * 99999999)).padStart(8, "0");
  const mod = String(payload.modelo || 65);
  const serie = String(payload.serie || 1);
  const numero = String(payload.numero || 1);
  const cnpj = onlyNumbers(payload.emitente?.cnpj);
  const cMun = String(payload.emitente?.codigo_municipio || "5212501");

  const aamm = new Date().toISOString().slice(2, 7).replace("-", "");
  const chaveFake = `${cUF}${aamm}${cnpj.padStart(14, "0")}${mod}${serie.padStart(3, "0")}${numero.padStart(9, "0")}1${cNF}0`;

  const root = create({ version: "1.0", encoding: "UTF-8" })
    .ele("NFe", { xmlns: "http://www.portalfiscal.inf.br/nfe" });

  const infNFe = root.ele("infNFe", {
    versao: "4.00",
    Id: `NFe${chaveFake}`
  });

  const ide = infNFe.ele("ide");
  ide.ele("cUF").txt(cUF);
  ide.ele("cNF").txt(cNF);
  ide.ele("natOp").txt(payload.natureza_operacao || "VENDA");
  ide.ele("mod").txt(mod);
  ide.ele("serie").txt(serie);
  ide.ele("nNF").txt(numero);
  ide.ele("dhEmi").txt(dhEmi);
  ide.ele("tpNF").txt("1");
  ide.ele("idDest").txt("1");
  ide.ele("cMunFG").txt(cMun);
  ide.ele("tpImp").txt("4");
  ide.ele("tpEmis").txt("1");
  ide.ele("cDV").txt("0");
  ide.ele("tpAmb").txt(tpAmb);
  ide.ele("finNFe").txt("1");
  ide.ele("indFinal").txt("1");
  ide.ele("indPres").txt("4");
  ide.ele("procEmi").txt("0");
  ide.ele("verProc").txt("1.0.0");

  const emit = infNFe.ele("emit");
  emit.ele("CNPJ").txt(cnpj);
  emit.ele("xNome").txt(payload.emitente?.razao_social || "");
  emit.ele("xFant").txt(payload.emitente?.nome_fantasia || payload.emitente?.razao_social || "");

  const enderEmit = emit.ele("enderEmit");
  enderEmit.ele("xLgr").txt("NAO INFORMADO");
  enderEmit.ele("nro").txt("SN");
  enderEmit.ele("xBairro").txt("CENTRO");
  enderEmit.ele("cMun").txt(cMun);
  enderEmit.ele("xMun").txt(payload.emitente?.cidade || "LUZIANIA");
  enderEmit.ele("UF").txt(payload.emitente?.uf || "GO");
  enderEmit.ele("cPais").txt("1058");
  enderEmit.ele("xPais").txt("BRASIL");

  emit.ele("IE").txt(onlyNumbers(payload.emitente?.inscricao_estadual));
  emit.ele("CRT").txt(payload.emitente?.regime_tributario === "simples_nacional" ? "1" : "3");

  if (payload.destinatario?.cpf) {
    const dest = infNFe.ele("dest");
    dest.ele("CPF").txt(onlyNumbers(payload.destinatario.cpf));
    if (payload.destinatario.nome) {
      dest.ele("xNome").txt(payload.destinatario.nome);
    }
    dest.ele("indIEDest").txt("9");
  }

  let totalProdutos = 0;

  for (const item of payload.itens || []) {
    totalProdutos += safeNumber(item.valor_total);

    const det = infNFe.ele("det", { nItem: String(item.numero_item) });
    const prod = det.ele("prod");

    prod.ele("cProd").txt(String(item.codigo_produto || item.numero_item));
    prod.ele("cEAN").txt("SEM GTIN");
    prod.ele("xProd").txt(item.descricao || "ITEM");
    prod.ele("NCM").txt(item.ncm || "21069090");
    prod.ele("CFOP").txt(item.cfop || "5102");
    prod.ele("uCom").txt(item.unidade || "UN");
    prod.ele("qCom").txt(safeNumber(item.quantidade, 1).toFixed(4));
    prod.ele("vUnCom").txt(safeNumber(item.valor_unitario).toFixed(2));
    prod.ele("vProd").txt(safeNumber(item.valor_total).toFixed(2));
    prod.ele("cEANTrib").txt("SEM GTIN");
    prod.ele("uTrib").txt(item.unidade || "UN");
    prod.ele("qTrib").txt(safeNumber(item.quantidade, 1).toFixed(4));
    prod.ele("vUnTrib").txt(safeNumber(item.valor_unitario).toFixed(2));
    prod.ele("indTot").txt("1");

    const imposto = det.ele("imposto");
    imposto.ele("vTotTrib").txt("0.00");

    const icms = imposto.ele("ICMS");
    const icmssn102 = icms.ele("ICMSSN102");
    icmssn102.ele("orig").txt("0");
    icmssn102.ele("CSOSN").txt("102");

    const pis = imposto.ele("PIS");
    const pisnt = pis.ele("PISNT");
    pisnt.ele("CST").txt("07");

    const cofins = imposto.ele("COFINS");
    const cofinsnt = cofins.ele("COFINSNT");
    cofinsnt.ele("CST").txt("07");
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
  total.ele("vProd").txt(totalProdutos.toFixed(2));
  total.ele("vFrete").txt("0.00");
  total.ele("vSeg").txt("0.00");
  total.ele("vDesc").txt("0.00");
  total.ele("vII").txt("0.00");
  total.ele("vIPI").txt("0.00");
  total.ele("vIPIDevol").txt("0.00");
  total.ele("vPIS").txt("0.00");
  total.ele("vCOFINS").txt("0.00");
  total.ele("vOutro").txt("0.00");
  total.ele("vNF").txt(safeNumber(payload.totais?.valor_total, totalProdutos).toFixed(2));
  total.ele("vTotTrib").txt("0.00");

  const transp = infNFe.ele("transp");
  transp.ele("modFrete").txt("9");

  const pag = infNFe.ele("pag");
  const detPag = pag.ele("detPag");
  detPag.ele("tPag").txt(payload.pagamento?.forma_codigo || "01");
  detPag.ele("vPag").txt(safeNumber(payload.pagamento?.valor, totalProdutos).toFixed(2));

  const infAdic = infNFe.ele("infAdic");
  infAdic.ele("infCpl").txt(
    tpAmb === "2"
      ? "EMITIDA EM AMBIENTE DE HOMOLOGACAO - SEM VALOR FISCAL"
      : (payload.informacoes_complementares || "Pedido emitido pelo sistema")
  );

  const xml = root.end({ prettyPrint: true });
  return { xml, chaveFake };
}

async function gerarDanfeBase64(payload: any, numero: number, chaveAcesso: string) {
  const doc = new PDFDocument({ margin: 20, size: "A4" });
  const buffers: Buffer[] = [];

  doc.on("data", (chunk) => buffers.push(chunk));
  const done = new Promise<Buffer>((resolve) => {
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
    doc.text(
      `${item.numero_item}. ${item.descricao} | Qtd: ${item.quantidade} | Unit: ${safeNumber(item.valor_unitario).toFixed(2)} | Total: ${safeNumber(item.valor_total).toFixed(2)}`
    );
  }

  doc.moveDown();
  doc.text(`Valor total: ${safeNumber(payload.totais?.valor_total).toFixed(2)}`);

  const qrData = `CHAVE=${chaveAcesso}`;
  const qrDataUrl = await QRCode.toDataURL(qrData);
  const qrBase64 = qrDataUrl.replace(/^data:image\/png;base64,/, "");
  const qrBuffer = Buffer.from(qrBase64, "base64");

  doc.moveDown();
  doc.text("QR Code:");
  doc.image(qrBuffer, { fit: [120, 120] });

  doc.end();

  const pdfBuffer = await done;
  return pdfBuffer.toString("base64");
}

async function uploadTexto(bucket: string, path: string, content: string, contentType: string) {
  const url = `${STORAGE_API_URL}/object/${bucket}/${path}`;

  const response = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
      apikey: SUPABASE_SERVICE_ROLE_KEY,
      "Content-Type": contentType,
      "x-upsert": "true"
    },
    body: Buffer.from(content, "utf-8")
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Erro ao enviar arquivo para ${bucket}: ${errorText}`);
  }
}

async function uploadBase64(bucket: string, path: string, base64: string, contentType: string) {
  const buffer = Buffer.from(base64, "base64");
  const url = `${STORAGE_API_URL}/object/${bucket}/${path}`;

  const response = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
      apikey: SUPABASE_SERVICE_ROLE_KEY,
      "Content-Type": contentType,
      "x-upsert": "true"
    },
    body: buffer
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Erro ao enviar arquivo para ${bucket}: ${errorText}`);
  }
}

app.get("/", (_req, res) => {
  res.send("Servidor fiscal rodando 🚀");
});

app.get("/health", (_req, res) => {
  res.json({ ok: true, service: "nfce-backend" });
});

app.post("/nfce/emitir-teste", async (_req, res) => {
  return res.json({
    ok: true,
    mensagem: "Rota de teste funcionando"
  });
});

async function emitirNfceHandler(orderId: string, payload: any, res: express.Response) {
  try {
    if (!orderId) {
      return res.status(400).json({
        autorizado: false,
        status: "ERROR",
        motivo: "orderId não informado"
      });
    }

    if (!payload?.emitente?.cnpj || !payload?.certificado?.senha) {
      return res.status(400).json({
        autorizado: false,
        status: "ERROR",
        motivo: "Payload fiscal incompleto"
      });
    }

    const certBuffer = await obterCertificadoBuffer(payload);
    validarCertificadoP12(certBuffer, payload.certificado.senha);

    const { xml, chaveFake } = gerarXmlBase(payload);

    const numero = Number(payload.numero || 1);
    const serie = Number(payload.serie || 1);

    const chaveAcesso =
      payload.ambiente === 2
        ? chaveFake
        : `5226${Date.now()}${String(numero).padStart(6, "0")}`;

    const tenantId = payload.tenant_id || "sem-tenant";
    const xmlPath = `${tenantId}/nfce_${numero}.xml`;
    const danfePath = `${tenantId}/danfe_${numero}.pdf`;

    await uploadTexto(XML_BUCKET, xmlPath, xml, "application/xml");

    const danfeBase64 = await gerarDanfeBase64(payload, numero, chaveAcesso);
    await uploadBase64(DANFE_BUCKET, danfePath, danfeBase64, "application/pdf");

    return res.json({
      autorizado: true,
      status: "AUTHORIZED",
      numero,
      serie,
      chave_acesso: chaveAcesso,
      protocolo: payload.ambiente === 2 ? "HOMOLOGACAO-LOCAL" : "PRODUCAO-LOCAL",
      xml_path: xmlPath,
      danfe_path: danfePath
    });
  } catch (err: any) {
    console.error("Erro no backend fiscal:", err);

    return res.status(500).json({
      autorizado: false,
      status: "ERROR",
      motivo: err.message || "Erro interno no backend fiscal"
    });
  }
}

app.post("/nfce/emitir/:orderId", async (req, res) => {
  return emitirNfceHandler(req.params.orderId, req.body, res);
});

app.post("/nfce/emitir-pedido/:pedidoId", async (req, res) => {
  return emitirNfceHandler(req.params.pedidoId, req.body, res);
});

app.post("/nfce/provider-callback", async (req, res) => {
  const auth = req.headers.authorization || "";
  const expected = `Bearer ${process.env.FISCAL_PROVIDER_TOKEN}`;

  if (auth !== expected) {
    return res.status(401).json({ ok: false, error: "Não autorizado" });
  }

  return res.json({ ok: true });
});

app.listen(PORT, () => {
  console.log(`🚀 Backend fiscal externo rodando em http://localhost:${PORT}`);
});