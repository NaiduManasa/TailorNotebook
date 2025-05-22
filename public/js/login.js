// public/js/login.js

document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('login-form');
  
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
  
      const username = form.username.value.trim();
      const password = form.password.value;
  
      if (!username || !password) {
        alert('Please enter both username and password.');
        return;
      }
  
      try {
        const response = await fetch('/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, password })
        });
  
        const result = await response.json();
  
        if (response.ok) {
          alert(result.message || 'Login successful!');
          window.location.href = 'dashboard.html'; // Change this if your post-login page is different
        } else {
          alert(result.error || 'Login failed. Invalid credentials.');
        }
      } catch (err) {
        console.error('Error during login:', err);
        alert('Something went wrong. Please try again later.');
      }
    });
  });
  