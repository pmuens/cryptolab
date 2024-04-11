import express from "npm:express@4";

const app = express();

// deno-lint-ignore no-explicit-any
app.get("/", (_request: any, response: any) => {
  response.send("Hello from Express!");
});

app.listen(3000);
