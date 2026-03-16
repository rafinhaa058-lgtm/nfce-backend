"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const cors_1 = __importDefault(require("cors"));
const dotenv_1 = __importDefault(require("dotenv"));
const supabase_js_1 = require("@supabase/supabase-js");
dotenv_1.default.config();
const app = (0, express_1.default)();
app.use((0, cors_1.default)());
app.use(express_1.default.json());
const supabase = (0, supabase_js_1.createClient)(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);
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
    }
    catch (err) {
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
    }
    catch (err) {
        return res.status(500).json({
            erro: "Erro interno",
            detalhe: err.message
        });
    }
});
app.listen(PORT, () => {
    console.log(`Servidor fiscal rodando na porta ${PORT}`);
});
