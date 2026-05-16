/**
 * Static recipe registry. Bun-compile-safe: every provider is a static import.
 *
 * Adding a new openai-compatible provider = add a file here + register below.
 * Adding a new native provider = ALSO wire the factory in gateway.ts.
 */

import type { Recipe } from "../types.js";
import { anthropic } from "./anthropic.js";
import { azureOpenAI } from "./azure-openai.js";
import { dashscope } from "./dashscope.js";
import { deepseek } from "./deepseek.js";
import { google } from "./google.js";
import { groq } from "./groq.js";
import { litellmProxy } from "./litellm-proxy.js";
import { llamaServer } from "./llama-server.js";
import { minimax } from "./minimax.js";
import { ollama } from "./ollama.js";
import { openai } from "./openai.js";
import { together } from "./together.js";
import { voyage } from "./voyage.js";
import { zeroentropyai } from "./zeroentropyai.js";
import { zhipu } from "./zhipu.js";

const ALL: Recipe[] = [
  openai,
  google,
  anthropic,
  ollama,
  voyage,
  litellmProxy,
  deepseek,
  groq,
  together,
  llamaServer,
  minimax,
  dashscope,
  zhipu,
  azureOpenAI,
  zeroentropyai,
];

/** Map from `provider:id` key to recipe. */
export const RECIPES: Map<string, Recipe> = new Map(ALL.map((r) => [r.id, r]));

export function getRecipe(id: string): Recipe | undefined {
  return RECIPES.get(id);
}

export function listRecipes(): Recipe[] {
  return [...ALL];
}
