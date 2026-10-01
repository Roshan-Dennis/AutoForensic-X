/* app.js — shared client-side helpers.
   Currently just the Cytoscape.js lineage-graph renderer, reused by the
   Incident Graph View and the Process Entity page (same underlying
   ancestor/descendant lineage query, same visual treatment). */

function renderLineageGraph(containerId, jsonUrl) {
  fetch(jsonUrl).then(r => r.json()).then(data => {
    const container = document.getElementById(containerId);
    if (!data.nodes || data.nodes.length === 0) {
      container.innerHTML = '<div class="empty-state">No process lineage captured for this entry (likely an isolated event with no recorded parent).</div>';
      return;
    }

    const elements = [];
    data.nodes.forEach(n => {
      let cls = 'proc';
      if (n.exec_id === data.root_exec_id) cls += ' root';
      if (n.exec_id === data.focus_exec_id) cls += ' focus';
      elements.push({
        data: {
          id: n.exec_id,
          label: n.binary + '\npid ' + n.pid,
          title: n.arguments || n.full_binary || '',
        },
        classes: cls,
      });
    });
    data.edges.forEach(e => {
      elements.push({ data: { id: e.source + '->' + e.target, source: e.source, target: e.target } });
    });

    const cy = cytoscape({
      container: container,
      elements: elements,
      layout: { name: 'breadthfirst', directed: true, spacingFactor: 1.3, padding: 20 },
      style: [
        {
          selector: 'node',
          style: {
            'background-color': '#1e2430',
            'border-width': 2,
            'border-color': '#5a8dee',
            'label': 'data(label)',
            'color': '#e8ecf3',
            'font-size': 10,
            'text-wrap': 'wrap',
            'text-valign': 'center',
            'text-halign': 'center',
            'width': 90,
            'height': 44,
            'shape': 'round-rectangle',
          }
        },
        {
          selector: 'node.root',
          style: { 'border-color': '#3ddc97', 'border-width': 3 }
        },
        {
          selector: 'node.focus',
          style: { 'background-color': '#3a1f26', 'border-color': '#ef4b6a', 'border-width': 3 }
        },
        {
          selector: 'edge',
          style: {
            'width': 1.5,
            'line-color': '#3a4252',
            'target-arrow-color': '#3a4252',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
          }
        },
      ],
    });
    cy.on('tap', 'node', evt => {
      window.location = '/entity/process/' + evt.target.id();
    });
    cy.fit(undefined, 30);
  }).catch(() => {
    document.getElementById(containerId).innerHTML = '<div class="empty-state">Could not load lineage graph.</div>';
  });
}
