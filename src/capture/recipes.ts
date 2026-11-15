/**
 * Login recipes for `zks capture login --recipe NAME`: the non-secret flags of a known login form.
 * Explicit flags always win. verified:false means the selectors come from the site's public
 * documentation and have not been confirmed on a real run yet.
 */
export interface LoginRecipe {
  /** null: the site lives on the user's own host, so --origin is required. */
  origin: string | null;
  /** null: the login form is served at the origin itself (`<origin>/`). */
  url: string | null;
  userSelector: string;
  passwordSelector: string;
  submitSelector: string;
  successSelector: string | null;
  requiresOrigin: boolean;
  verified: boolean;
}

export const LOGIN_RECIPES: Record<string, LoginRecipe> = {
  hostgator: {
    origin: "https://portal.hostgator.com",
    url: "https://portal.hostgator.com/login",
    userSelector: "input[name=email]",
    passwordSelector: "input[name=password]",
    submitSelector: "button[type=submit]",
    successSelector: null,
    requiresOrigin: false,
    verified: false,
  },
  github: {
    origin: "https://github.com",
    url: "https://github.com/login",
    userSelector: "#login_field",
    passwordSelector: "#password",
    submitSelector: "input[type=submit]",
    successSelector: null,
    requiresOrigin: false,
    verified: false,
  },
  vercel: {
    origin: "https://vercel.com",
    url: "https://vercel.com/login",
    userSelector: "input[name=email]",
    passwordSelector: "input[name=password]",
    submitSelector: "button[type=submit]",
    successSelector: null,
    requiresOrigin: false,
    verified: false,
  },
  railway: {
    origin: "https://railway.com",
    url: "https://railway.com/login",
    userSelector: "input[name=email]",
    passwordSelector: "input[name=password]",
    submitSelector: "button[type=submit]",
    successSelector: null,
    requiresOrigin: false,
    verified: false,
  },
  supabase: {
    origin: "https://supabase.com",
    url: "https://supabase.com/dashboard/sign-in",
    userSelector: "input[type=email]",
    passwordSelector: "input[type=password]",
    submitSelector: "button[type=submit]",
    successSelector: null,
    requiresOrigin: false,
    verified: false,
  },
  netlify: {
    origin: "https://app.netlify.com",
    url: "https://app.netlify.com/login",
    userSelector: "input[name=email]",
    passwordSelector: "input[name=password]",
    submitSelector: "button[type=submit]",
    successSelector: null,
    requiresOrigin: false,
    verified: false,
  },
  cloudflare: {
    origin: "https://dash.cloudflare.com",
    url: "https://dash.cloudflare.com/login",
    userSelector: "input[name=email]",
    passwordSelector: "input[name=password]",
    submitSelector: "button[type=submit]",
    successSelector: null,
    requiresOrigin: false,
    verified: false,
  },
  cpanel: {
    origin: null,
    url: null,
    userSelector: "#user",
    passwordSelector: "#pass",
    submitSelector: "#login_submit",
    successSelector: null,
    requiresOrigin: true,
    verified: false,
  },
};

/** The recipe of that exact name, or null; never a prototype key. */
export function loginRecipe(name: string): LoginRecipe | null {
  return Object.hasOwn(LOGIN_RECIPES, name) ? (LOGIN_RECIPES[name] as LoginRecipe) : null;
}
