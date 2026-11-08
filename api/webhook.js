export default async function handler(req, res) {
  // LINEからのPOST以外は拒否
  if (req.method !== "POST") {
    return res.status(405).send("Method Not Allowed");
  }

  try {
    // LINEから受け取ったデータ
    const body = req.body;

    // Google Apps ScriptのWebhook URL
    const gasUrl = process.env.GAS_WEBHOOK_URL;

    if (!gasUrl) {
      console.error("GAS_WEBHOOK_URL is not set");
      return res.status(500).send("GAS_WEBHOOK_URL is not set");
    }

    // Google Apps Scriptへ転送
    const response = await fetch(gasUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(body)
    });

    console.log("GAS response:", response.status);

    // LINEには必ず200を返す
    return res.status(200).send("OK");

  } catch (error) {

    console.error("Webhook error:", error);

    // LINEには200を返す
    return res.status(200).send("OK");
  }
}
