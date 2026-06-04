(function () {
  const form = document.getElementById("login-form");
  const status = document.getElementById("auth-status");
  if (!form) return;

  form.addEventListener("submit", async (evt) => {
    evt.preventDefault();
    const data = new FormData(form);
    status.textContent = "signing in...";
    try {
      const resp = await fetch("/api/v1/auth/token", {
        method: "POST",
        body: data,
      });
      if (!resp.ok) {
        status.textContent = "auth failed: " + resp.status;
        return;
      }
      const json = await resp.json();
      sessionStorage.setItem("pegase_token", json.access_token);
      status.textContent = "signed in. token stored in sessionStorage.";
    } catch (err) {
      status.textContent = "error: " + err.message;
    }
  });
})();
