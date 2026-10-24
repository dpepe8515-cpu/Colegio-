document.querySelectorAll('[data-toggle]').forEach(b=>b.addEventListener('click',()=>{const t=document.getElementById(b.dataset.toggle);const o=t.classList.toggle('open');b.setAttribute('aria-expanded',o)}));
document.querySelectorAll('.gal img').forEach(i=>i.addEventListener('click',()=>{const d=document.getElementById('lb');d.querySelector('img').src=i.src;d.querySelector('p').textContent=i.alt;d.showModal()}));
const lb=document.getElementById('lb');if(lb)lb.addEventListener('click',()=>lb.close());
