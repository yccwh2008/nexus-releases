"use strict";

const versionPattern = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/;

function validateCatalog(value) {
  if (!value || typeof value.version !== "string" || !versionPattern.test(value.version) ||
      value.archive !== `Nexus-${value.version}.zip` ||
      value.manifest !== `Nexus-${value.version}.manifest.json` ||
      !Number.isSafeInteger(value.archive_size) || value.archive_size <= 0 ||
      typeof value.archive_sha256 !== "string" || !/^[a-f0-9]{64}$/.test(value.archive_sha256)) {
    throw new Error("catalog_invalid");
  }
  return value;
}

function compareVersions(left, right) {
  const a = left.split(".").map(BigInt);
  const b = right.split(".").map(BigInt);
  for (let index = 0; index < 3; index++) {
    if (a[index] !== b[index]) return a[index] > b[index] ? 1 : -1;
  }
  return 0;
}

async function readJson(name) {
  const response = await fetch(new URL(name, window.location.href), {
    cache: "no-store", redirect: "error", credentials: "omit"
  });
  if (!response.ok || response.redirected) throw new Error("catalog_unavailable");
  return response.json();
}

function localLink(name) {
  const url = new URL(name, window.location.href);
  if (url.origin !== window.location.origin) throw new Error("cross_origin_download");
  return url.href;
}

async function showRelease() {
  const status = document.getElementById("status");
  try {
    const latest = validateCatalog(await readJson("latest.json"));
    const history = await readJson("releases.json");
    if (!Array.isArray(history) || !history.length) throw new Error("history_invalid");
    history.forEach(validateCatalog);
    if (history.some(item => compareVersions(item.version, latest.version) > 0)) {
      throw new Error("history_latest_mismatch");
    }
    if (!history.some(item => JSON.stringify(item) === JSON.stringify(latest))) {
      // 服务端 JSON 键顺序不属于清单契约。
      const match = history.find(item => item.version === latest.version);
      if (!match || ["archive", "manifest", "archive_size", "archive_sha256"].some(key => match[key] !== latest[key])) {
        throw new Error("history_mismatch");
      }
    }
    document.getElementById("version").textContent = latest.version;
    document.getElementById("size").textContent = `${(latest.archive_size / 1048576).toFixed(1)} MiB（${latest.archive_size.toLocaleString("zh-CN")} 字节）`;
    document.getElementById("sha256").textContent = latest.archive_sha256;
    for (const [id, name] of [["archive", latest.archive], ["manifest", latest.manifest], ["installer", "install.ps1"]]) {
      document.getElementById(id).href = localLink(name);
    }
    document.getElementById("install-command").textContent =
      `Get-FileHash .\\${latest.archive} -Algorithm SHA256\n` +
      `powershell -NoProfile -ExecutionPolicy Bypass -File .\\install.ps1 -Zip .\\${latest.archive} -Manifest .\\${latest.manifest}`;
    const list = document.getElementById("history");
    for (const item of [...history].reverse()) {
      const row = document.createElement("li");
      const link = document.createElement("a");
      link.textContent = `Nexus ${item.version} · ZIP`;
      link.href = localLink(item.archive);
      link.download = item.archive;
      const manifest = document.createElement("a");
      manifest.textContent = "manifest";
      manifest.href = localLink(item.manifest);
      manifest.download = item.manifest;
      row.append(link, " / ", manifest);
      list.append(row);
    }
    document.getElementById("release").hidden = false;
    status.textContent = "版本信息来自本站 latest.json。下载后请核对 SHA-256。";
  } catch (error) {
    document.getElementById("release").hidden = true;
    status.textContent = error.message === "history_latest_mismatch"
      ? "版本清单已切换，请刷新页面后重试。"
      : "暂时无法验证本站版本清单，未确认可用下载；请稍后重试。";
  }
}

showRelease();
