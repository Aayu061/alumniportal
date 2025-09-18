// Replace localhost with your Render service URL
const API_BASE = 'https://alumniportal-jg5p.onrender.com';

/* Central script for auth, users, contact - localStorage only */

/* Register new user (adds to users array) */
function register(event){
  event.preventDefault();
  const name = document.getElementById('name').value.trim();
  const email = document.getElementById('email').value.trim().toLowerCase();
  const password = document.getElementById('password').value;
  const confirm = document.getElementById('confirmPassword').value;
  const msg = document.getElementById('registerMsg');
  msg.style.color = 'red';

  if(!name || !email || !password || !confirm){ msg.textContent = 'Please fill all fields.'; return; }
  if(password.length < 6){ msg.textContent = 'Password should be at least 6 characters.'; return; }
  if(password !== confirm){ msg.textContent = 'Passwords do not match.'; return; }
  fetch(`${API_BASE}/api/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, email, password })
  })
  .then(res => res.json())
  .then(data => {
    if(data.error){ msg.textContent = data.error; msg.style.color = 'red'; return; }
    msg.style.color = 'green'; msg.textContent = 'Registration successful! You can now login.';
    document.getElementById('registerForm').reset();
    setTimeout(()=>{ msg.textContent = ''; }, 2500);
  })
  .catch(()=>{ msg.textContent = 'Server error.'; });
}

/* Login - checks users array and sets currentUser (session) */
function login(){
  const email = document.getElementById('loginEmail').value.trim().toLowerCase();
  const password = document.getElementById('loginPassword').value;
  const msg = document.getElementById('loginMsg');
  msg.style.color = 'red';
  fetch(`${API_BASE}/api/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password })
  })
  .then(res => res.json())
  .then(data => {
    if(data.error){ msg.textContent = data.error; return; }
    // Save token and user info in localStorage
    localStorage.setItem('token', data.token);
    localStorage.setItem('currentUser', JSON.stringify({ name: data.name, email: data.email, is_admin: data.is_admin }));
    msg.style.color = 'green'; msg.textContent = 'Login successful! Redirecting...';
    setTimeout(()=>{ window.location.href = 'welcome.html'; }, 900);
  })
  .catch(()=>{ msg.textContent = 'Server error.'; });
}

/* Contact form - save messages (simple) */
document.addEventListener('DOMContentLoaded', ()=>{
  const contact = document.getElementById('contactForm');
  if(contact){
    contact.addEventListener('submit', (e)=>{
      e.preventDefault();
      const name = document.getElementById('contactName').value.trim();
      const email = document.getElementById('contactEmail').value.trim();
      const message = document.getElementById('contactMessage').value.trim();
      const out = document.getElementById('contactMsg');
      if(!name || !email || !message){ out.textContent = 'Please fill all fields.'; out.style.color='red'; return; }
      const msgs = JSON.parse(localStorage.getItem('messages')) || [];
      msgs.push({ name, email, message, date: new Date().toISOString() });
      localStorage.setItem('messages', JSON.stringify(msgs));
      out.style.color='green'; out.textContent = 'Message sent — thank you!';
      contact.reset();
      setTimeout(()=>{ out.textContent = ''; }, 2500);
    });
  }
});

/* helper to fill test credentials (for demo) */
function fillTest(){
  // create demo user if missing
  const users = JSON.parse(localStorage.getItem('users')) || [];
  if(!users.find(u=>u.email==='test@demo.com')){
    users.push({ name:'Demo User', email:'test@demo.com', password:'demo123' });
    localStorage.setItem('users', JSON.stringify(users));
  }
  document.getElementById('loginEmail').value = 'test@demo.com';
  document.getElementById('loginPassword').value = 'demo123';
}

/* small utility to ensure clicking Home doesn't log out current user */
// index.html has no logout on Home; welcome checks currentUser on load
