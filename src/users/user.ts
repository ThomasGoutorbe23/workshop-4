import bodyParser from "body-parser";
import express from "express";
import { createRandomSymmetricKey, exportSymKey, rsaEncrypt, symEncrypt } from "../crypto";
import { REGISTRY_PORT, BASE_ONION_ROUTER_PORT, BASE_USER_PORT } from "../config";

let lastCircuit: number[] | null = null;

export type SendMessageBody = {
  message: string;
  destinationUserId: number;
};

export async function user(userId: number) {
  const _user = express();
  _user.use(express.json());
  _user.use(bodyParser.json());

  let lastReceivedMessage: string | null = null;
  let lastSentMessage: string | null = null;

  _user.get("/status", (req, res) => {
    res.send("live");
  });

  _user.get("/getLastReceivedMessage", (req, res) => {
    res.json({ result: lastReceivedMessage });
  });

  _user.get("/getLastSentMessage", (req, res) => {
    res.json({ result: lastSentMessage });
  });

  _user.get("/getLastCircuit", (req, res) => {
    res.json({ result: lastCircuit });
  });

  _user.post("/message", (req, res) => {
    const { message } = req.body;
    lastReceivedMessage = message;
    res.send("success");
  });

  _user.post("/sendMessage", async (req, res) => {
    const { message, destinationUserId } = req.body;

    try {
      // Get node list
      const response = await fetch(`http://localhost:${REGISTRY_PORT}/getNodeRegistry`);
      const { nodes } = (await response.json()) as { nodes: { nodeId: number; pubKey: string }[] };

      if (nodes.length < 3) {
        res.status(500).json({ error: "Not enough nodes" });
        return;
      }

      // Select 3 random nodes
      const shuffled = [...nodes].sort(() => 0.5 - Math.random());
      const circuit = shuffled.slice(0, 3);

      // Generaate symmetric keys
      const symKeys = await Promise.all(
          Array(3).fill(0).map(() => createRandomSymmetricKey())
      );
      const exportedSymKeys = await Promise.all(
          symKeys.map(k => exportSymKey(k))
      );

      // Build message layers
      let payload = message;
      for (let i = 2; i >= 0; i--) {
        const destination = i === 2
            ? BASE_USER_PORT + destinationUserId
            : BASE_ONION_ROUTER_PORT + circuit[i + 1].nodeId;

        const destinationStr = destination.toString().padStart(10, "0");
        const innerPayload = destinationStr + payload;

        const encryptedInner = await symEncrypt(symKeys[i], innerPayload);
        const encryptedSymKey = await rsaEncrypt(exportedSymKeys[i], circuit[i].pubKey);

        payload = encryptedSymKey + encryptedInner;
      }

      // Send it to the first node
      await fetch(`http://localhost:${BASE_ONION_ROUTER_PORT + circuit[0].nodeId}/message`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: payload }),
      });

      lastSentMessage = message;
      lastCircuit = circuit.map(n => n.nodeId);
      res.send("success");
    } catch (err) {
      console.error("Error sending message:", err);
      res.status(500).json({ error: "Failed to send message" });
    }
  });

  const server = _user.listen(BASE_USER_PORT + userId, () => {
    console.log(`User ${userId} listening on port ${BASE_USER_PORT + userId}`);
  });

  return server;
}