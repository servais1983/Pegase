(function () {
  const SEV_COLOR = {
    critical: "#c0392b",
    high: "#e67e22",
    medium: "#f1c40f",
    low: "#2ecc71",
    info: "#5d6d7e",
  };

  const status = document.getElementById("status");
  const tokenInput = document.getElementById("token");
  tokenInput.value = sessionStorage.getItem("pegase_token") || "";

  document.getElementById("load").addEventListener("click", load);

  async function load() {
    const mission = document.getElementById("mission").value.trim();
    const token = tokenInput.value.trim();
    if (!mission) {
      status.textContent = "enter a mission id";
      return;
    }
    sessionStorage.setItem("pegase_token", token);
    status.textContent = "loading...";
    try {
      const resp = await fetch(`/api/v1/reports/${mission}/graph.json`, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      if (!resp.ok) {
        status.textContent = "error: HTTP " + resp.status;
        return;
      }
      const graph = await resp.json();
      render(graph);
      status.textContent = `${graph.nodes.length} nodes, ${graph.edges.length} edges`;
    } catch (e) {
      status.textContent = "error: " + e.message;
    }
  }

  function render(graph) {
    const svg = d3.select("#graph");
    svg.selectAll("*").remove();
    const width = svg.node().clientWidth;
    const height = svg.node().clientHeight;

    if (!graph.nodes.length) {
      svg.append("text").attr("x", 20).attr("y", 30).attr("fill", "#8b949e")
        .text("No nodes - run a mission with the postxploit module first.");
      return;
    }

    const links = graph.edges.map((e) => Object.assign({}, e));
    const nodes = graph.nodes.map((n) => Object.assign({}, n));

    const sim = d3.forceSimulation(nodes)
      .force("link", d3.forceLink(links).id((d) => d.id).distance(120))
      .force("charge", d3.forceManyBody().strength(-300))
      .force("center", d3.forceCenter(width / 2, height / 2));

    const link = svg.append("g").selectAll("line")
      .data(links).join("line")
      .attr("class", "link").attr("stroke-width", 1.5);

    const node = svg.append("g").selectAll("g")
      .data(nodes).join("g").attr("class", "node")
      .call(d3.drag()
        .on("start", (ev, d) => { if (!ev.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
        .on("drag", (ev, d) => { d.fx = ev.x; d.fy = ev.y; })
        .on("end", (ev, d) => { if (!ev.active) sim.alphaTarget(0); d.fx = null; d.fy = null; }));

    node.append("circle")
      .attr("r", (d) => 8 + (d.findings || 1) * 2)
      .attr("fill", (d) => SEV_COLOR[d.max_severity] || "#5d6d7e");

    node.append("title").text((d) => `${d.id}\nseverity: ${d.max_severity}\nfindings: ${d.findings}`);

    node.append("text").attr("x", 12).attr("y", 4).text((d) => d.id);

    sim.on("tick", () => {
      link.attr("x1", (d) => d.source.x).attr("y1", (d) => d.source.y)
          .attr("x2", (d) => d.target.x).attr("y2", (d) => d.target.y);
      node.attr("transform", (d) => `translate(${d.x},${d.y})`);
    });
  }
})();
