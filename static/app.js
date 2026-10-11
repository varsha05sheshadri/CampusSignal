const menu = document.getElementById('mobileMenu');
const sidebar = document.getElementById('sidebar');
if (menu && sidebar) menu.addEventListener('click', () => sidebar.classList.toggle('sidebar-open'));
