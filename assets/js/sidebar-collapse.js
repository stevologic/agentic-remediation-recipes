/*
 * Sidebar collapse defaults — security-recipes.ai.
 *
 * Keep left-nav tree menus collapsed by default, but preserve the open
 * ancestry for the current page (aria-current="page") so readers still
 * see context for where they are.
 */
(function () {
  'use strict';

  function collapseSidebar() {
    var sidebar = document.querySelector('.hextra-sidebar, aside nav, .nextra-sidebar');
    if (!sidebar) return;

    // Close every expanded disclosure tree first.
    sidebar.querySelectorAll('details[open]').forEach(function (node) {
      node.removeAttribute('open');
    });

    // Re-open only the ancestry chain for the current page.
    var current = sidebar.querySelector('[aria-current="page"]');
    if (!current) return;

    var parent = current.parentElement;
    while (parent) {
      if (parent.tagName && parent.tagName.toLowerCase() === 'details') {
        parent.setAttribute('open', '');
      }
      parent = parent.parentElement;
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', collapseSidebar);
  } else {
    collapseSidebar();
  }
})();
