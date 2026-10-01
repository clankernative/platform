for (const button of document.querySelectorAll('[data-security-action]')) {
  button.addEventListener('click', async () => {
    button.disabled = true;
    const message = document.querySelector('#credential-message');
    try {
      const sessionResponse = await fetch('/api/session');
      if (!sessionResponse.ok) throw new Error('Session unavailable');
      const session = await sessionResponse.json();
      button.dataset.invocation ??= crypto.randomUUID();
      const response = await fetch('/api/security-actions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': session.csrf_token,
          'Idempotency-Key': button.dataset.invocation,
        },
        body: JSON.stringify({
          operation: button.dataset.operation,
          payload: button.dataset.payload,
          product_return: button.dataset.productReturn,
        }),
      });
      if (!response.ok) throw new Error('Confirmation unavailable');
      const pending = await response.json();
      window.location.assign(pending.confirmation_url);
    } catch {
      message.textContent = 'Could not start confirmation. Please try again.';
      button.disabled = false;
    }
  });
}
