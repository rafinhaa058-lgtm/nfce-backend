import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import forge from "node-forge";
import { create } from "xmlbuilder2";
import axios from "axios";
import https from "https";
import { XMLParser } from "fast-xml-parser";
import { SignedXml } from "xml-crypto";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json({ limit: "30mb" }));

const PORT = Number(process.env.PORT || 3000);

const SEFAZ_GO = {
  prod: "https://nfe.sefaz.go.gov.br/nfe/services/NFeAutorizacao4",
  homo: "https://homolog.sefaz.go.gov.br/nfe/services/NFeAutorizacao4",
};

// ================= UTIL =================

const onlyNumbers = (v: any) => String(v || "").replace(/\D/g, "");

const pad = (v: any, size: number) => String(v).padStart(size, "0");

function calcularDV(chave: string) {
  let peso = 2;
  let soma = 0;

  for (let i = chave.length - 1; i >= 0; i--) {
    soma += Number(chave[i]) * peso;
    peso = peso === 9 ? 2 : peso + 1;
  }

  const mod = soma % 11;
  return mod === 0 || mod === 1 ? "0" : String(11 - mod);
}

// ================= XML =================

function gerarXml(payload: any) {
  const cUF = "52";
  const cNF = String(Math.floor(Math.random() * 99999999)).padStart(8, "0");
  const mod = "65";
  const serie = pad(payload.serie || 1, 3);
  const numero = pad(payload.numero || 1, 9);
  const cnpj = onlyNumbers(payload.emitente.cnpj);
  const aamm = new Date().toISOString().slice(2, 7).replace("-", "");

  const base = `${cUF}${aamm}${cnpj}${mod}${serie}${numero}1${cNF}`;
  const dv = calcularDV(base);
  const chave = base + dv;

  const root = create().ele("NFe", {
    xmlns: "http://www.portalfiscal.inf.br/nfe",
  });

  const inf = root.ele("infNFe", {
    Id: "NFe" + chave,
    versao: "4.00",
  });

  const ide = inf.ele("ide");
  ide.ele("cUF").txt(cUF);
  ide.ele("cNF").txt(cNF);
  ide.ele("natOp").txt("VENDA");
  ide.ele("mod").txt("65");
  ide.ele("serie").txt("1");
  ide.ele("nNF").txt(payload.numero || "1");
  ide.ele("dhEmi").txt(new Date().toISOString());
  ide.ele("tpNF").txt("1");
  ide.ele("idDest").txt("1");
  ide.ele("cMunFG").txt("5212501");
  ide.ele("tpImp").txt("4");
  ide.ele("tpEmis").txt("1");
  ide.ele("cDV").txt(dv);
  ide.ele("tpAmb").txt(payload.ambiente || "2");
  ide.ele("finNFe").txt("1");
  ide.ele("indFinal").txt("1");
  ide.ele("indPres").txt("1");
  ide.ele("procEmi").txt("0");
  ide.ele("verProc").txt("1.0");

  const emit = inf.ele("emit");
  emit.ele("CNPJ").txt(cnpj);
  emit.ele("xNome").txt(payload.emitente.razao_social);

  const ender = emit.ele("enderEmit");
  ender.ele("xLgr").txt("RUA MONÇÃO");
  ender.ele("nro").txt("30");
  ender.ele("xBairro").txt("CENTRO");
  ender.ele("cMun").txt("5212501");
  ender.ele("xMun").txt("LUZIANIA");
  ender.ele("UF").txt("GO");
  ender.ele("CEP").txt("72856472");
  ender.ele("cPais").txt("1058");
  ender.ele("xPais").txt("BRASIL");

  emit.ele("IE").txt(payload.emitente.inscricao_estadual);
  emit.ele("CRT").txt("1");

  let total = 0;

  payload.itens.forEach((item: any, i: number) => {
    const v = Number(item.valor_unitario);
    const q = Number(item.quantidade);
    const t = v * q;
    total += t;

    const det = inf.ele("det", { nItem: String(i + 1) });

    const prod = det.ele("prod");
    prod.ele("cProd").txt(String(i + 1));
    prod.ele("xProd").txt(item.descricao);
    prod.ele("NCM").txt("21069090");
    prod.ele("CFOP").txt("5102");
    prod.ele("uCom").txt("UN");
    prod.ele("qCom").txt(q.toFixed(2));
    prod.ele("vUnCom").txt(v.toFixed(2));
    prod.ele("vProd").txt(t.toFixed(2));
    prod.ele("indTot").txt("1");

    const imposto = det.ele("imposto");
    const icms = imposto.ele("ICMS").ele("ICMSSN102");
    icms.ele("orig").txt("0");
    icms.ele("CSOSN").txt("102");
  });

  const tot = inf.ele("total").ele("ICMSTot");
  tot.ele("vProd").txt(total.toFixed(2));
  tot.ele("vNF").txt(total.toFixed(2));

  return {
    xml: root.end({ headless: true }),
    chave,
  };
}

// ================= ASSINATURA =================

function assinar(xml: string, cert: string, key: string) {
  const sig = new SignedXml();
  sig.privateKey = key;
  sig.publicCert = cert;

  sig.addReference({
    xpath: "//*[local-name(.)='infNFe']",
    digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
    transforms: [
      "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
    ],
  });

  sig.computeSignature(xml);
  return sig.getSignedXml();
}

// ================= SEFAZ =================

async function enviar(xml: string, certBuffer: Buffer, senha: string) {
  const agent = new https.Agent({
    pfx: certBuffer,
    passphrase: senha,
    rejectUnauthorized: false,
  });

  const res = await axios.post(SEFAZ_GO.homo, xml, {
    httpsAgent: agent,
    headers: { "Content-Type": "application/xml" },
  });

  return res.data;
}

// ================= ROTA =================

app.post("/nfce/emitir/:id", async (req, res) => {
  try {
    console.log("🔥 RECEBIDO:", req.params.id);

    const payload = req.body;

    const certBuffer = Buffer.from(
      payload.certificado.pfx_base64,
      "base64"
    );

    const p12 = forge.pkcs12.pkcs12FromAsn1(
      forge.asn1.fromDer(certBuffer.toString("binary")),
      payload.certificado.senha
    );

    const bags = p12.getBags({
      bagType: forge.pki.oids.certBag,
    })[forge.pki.oids.certBag];

    const keyBags = p12.getBags({
      bagType: forge.pki.oids.pkcs8ShroudedKeyBag,
    })[forge.pki.oids.pkcs8ShroudedKeyBag];

    const certPem = forge.pki.certificateToPem(bags[0].cert);
    const keyPem = forge.pki.privateKeyToPem(keyBags[0].key);

    const { xml, chave } = gerarXml(payload);

    const xmlAssinado = assinar(xml, certPem, keyPem);

    const retorno = await enviar(
      xmlAssinado,
      certBuffer,
      payload.certificado.senha
    );

    return res.json({
      sucesso: true,
      chave_acesso: chave,
      resposta: retorno,
    });
  } catch (e: any) {
    console.error("ERRO:", e);

    return res.status(500).json({
      sucesso: false,
      erro: e.message,
    });
  }
});

// ================= START =================

app.listen(PORT, () => {
  console.log("🚀 NFCe rodando na porta", PORT);
});