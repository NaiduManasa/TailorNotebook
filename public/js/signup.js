// public/js/signup.js

document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('signup-form');
  
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
  
      const username = form.username.value.trim();
      const password = form.password.value;
  
      if (!username || !password) {
        alert('Please fill in both username and password.');
        return;
      }
  
      try {
        const response = await fetch('/signup', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, password })
        });
  
        const result = await response.json();
  
        if (response.ok) {
          alert(result.message || 'Signup successful!');
          window.location.href = 'login.html'; // Redirect to login page
        } else {
          alert(result.error || 'Signup failed. Username may already exist.');
        }
      } catch (err) {
        console.error('Error during signup:', err);
        alert('Something went wrong. Please try again later.');
      }
    });
});
