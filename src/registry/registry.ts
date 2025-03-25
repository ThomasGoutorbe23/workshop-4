import express from "express";
import bodyParser from "body-parser";
import { REGISTRY_PORT } from "../config";

export type GetNodeRegistryBody = {
  nodes: { nodeId: number; pubKey: string }[];
};

export async function registry() {
  const app = express();
  app.use(express.json());
  app.use(bodyParser.json());

  const nodeRegistry: { nodeId: number; pubKey: string }[] = [];

  app.get("/status", (req, res) => {
    res.send("live");
  });

  app.post("/registerNode", (req, res) => {
    nodeRegistry.push(req.body);
    res.json({ message: "Node registered successfully" });
  });

  app.get("/getNodeRegistry", (req, res) => {
    res.json({ nodes: nodeRegistry });
  });

  const server = app.listen(REGISTRY_PORT, () => {
    console.log(`Registry server is running on port ${REGISTRY_PORT}`);
  });

  return server;
}

export async function launchRegistry() {
  return registry();
}
