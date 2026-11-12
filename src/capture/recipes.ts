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
