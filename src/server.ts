import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { createClient } from "@supabase/supabase-js";

dotenv.config();

const app = express();

app.use(cors());
app.use(express.json());

const supabase = createClient(
  process.env.SUPABASE_URL as string,
  process.env.SUPABASE_SERVICE_ROLE_KEY as string
);

const PORT = process.env.PORT || 3000;

app.get("/", (_req, res) => {
  res.send("Servidor fiscal rodando 🚀");
});


// TESTE DE CONEXÃO COM BANCO
app.get("/teste-db", async (_req, res) => {
  try {

    const { data, error } = await supabase
      .from("pedidos")
      .select("*")
      .limit(5);

    if (error) {
      return res.status(500).json({
        erro: "Erro ao buscar pedidos",
        detalhe: error.message
      });
    }

    return res.json({
      ok: true,
      pedidos_encontrados: data?.length || 0,
      data
    });

  } catch (err: any) {

    return res.status(500).json({
      erro: "Erro interno",
      detalhe: err.message
    });

  }
});


// BUSCAR PEDIDO
app.get("/nfce/preparar/:orderId", async (req, res) => {

  try {

    const { orderId } = req.params;

    const { data, error } = await supabase
      .from("pedidos")
      .select("*")
      .eq("id", orderId)
      .single();

    if (error || !data) {
      return res.status(404).json({
        erro: "Pedido não encontrado",
        detalhe: error?.message
      });
    }

    return res.json({
      ok: true,
      pedido: data
    });

  } catch (err: any) {

    return res.status(500).json({
      erro: "Erro interno",
      detalhe: err.message
    });

  }

});


app.listen(PORT, () => {
  console.log(`Servidor fiscal rodando na porta ${PORT}`);
});