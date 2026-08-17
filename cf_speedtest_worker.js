// Cloudflare Worker 测速服务 (v2.1)
// 用途: 替代 speed.cloudflare.com 给 CF 优选IP 工具做带宽实测
//   请求 GET /__down?bytes=N   ->  精确返回 N 字节数据 (HEAD 同源仅带头)
// 部署: dash.cloudflare.com -> Workers & Pages -> Create Worker -> 粘贴本文件 -> Deploy
// 配置: 记下 worker 域名(如 myspeedtest.xxx.workers.dev), 在优选工具"测速域名"填入
//
// v2 修复要点(关键!):
//   1. 不再生成随机字节 -> 用 new Uint8Array(默认全0), 创建块近乎零 CPU
//      随机数生成循环在免费版 10ms CPU 限制下会把请求掐断
//   2. 不用 pull() 逐块推送 -> 在 start() 里一次性 enqueue 所有块,
//      建立满队列后 Cloudflare 直接零 CPU 流式下发, 不消耗每个请求的 10ms CPU
//   3. 流式响应不计 CPU(官方文档确认), 只要排队完成就能全速跑
//
// v2.1 修复:
//   - 精确返回 bytes 指定的字节数: 末块截断, 不再整块多送(之前 1MB 请求会发 2MB)
//   - bytes 超上限封顶(600MB), 防止超卖
//   - 支持 HEAD 请求(只返回 Content-Length, 不发 body), 便于客户端预检

const CHUNK_SIZE = 2 * 1024 * 1024;      // 每块 2MB (全零, 零CPU)
const MAX_CHUNKS = 300;                  // 最多 600MB(只存引用, 不占大内存)
const MAX_BYTES = CHUNK_SIZE * MAX_CHUNKS;

const CHUNK = new Uint8Array(CHUNK_SIZE); // 全零块, 重复引用即可

export default {
  async fetch(request) {
    const url = new URL(request.url);

    if (url.pathname !== "/__down") {
      return new Response(
        "CF speedtest worker ready (v2.1).\n" +
        "Usage: GET /__down?bytes=1048576\n",
        { headers: { "Content-Type": "text/plain; charset=utf-8" } }
      );
    }

    let want = parseInt(url.searchParams.get("bytes") || "1048576", 10);
    if (!Number.isFinite(want) || want <= 0) want = 1048576;
    want = Math.min(want, MAX_BYTES);

    const full = Math.floor(want / CHUNK_SIZE);   // 完整 2MB 块数
    const remain = want % CHUNK_SIZE;             // 末块剩余字节数

    const headers = {
      "Content-Type": "application/octet-stream",
      "Content-Length": String(want),
      "Access-Control-Allow-Origin": "*",
      "Cache-Control": "no-store",
    };

    if (request.method === "HEAD") {
      return new Response(null, { headers });
    }
    if (request.method !== "GET") {
      return new Response("Method Not Allowed", { status: 405 });
    }

    // 一次性排满队列: 之后 Cloudflare 流式下发, 全程零 CPU
    const stream = new ReadableStream({
      start(controller) {
        for (let i = 0; i < full; i++) controller.enqueue(CHUNK);
        if (remain > 0) controller.enqueue(CHUNK.subarray(0, remain));
        controller.close();
      },
      cancel() {},
    });

    return new Response(stream, { headers });
  },
};