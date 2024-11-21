function showPassword(serviceId) {
    fetch(`/decrypt/${serviceId}`)
        .then(response => response.json())
        .then(data => {
            document.getElementById(`password_${serviceId}`).textContent = data.password;
        });
}

function hidePassword(serviceId) {
    document.getElementById(`password_${serviceId}`).textContent = "Password Hidden";
}

function update(serviceId) {
    // Create a form to send the selected service_id to the backend
    var formdata = new FormData();
    formdata.append('service_id', serviceId);

    // Fetch the endpoint
    fetch('/process-service-id', {
        method: 'POST',
        body: formdata,
    }) // Process the response from the server, ensure status is ok
    .then( response => {
        if (!response.ok) {
            throw new Error('Network response was not ok ' + response.statusText);
        }
        return response.json;
    }) // Handle data 
    .then(data => {
        console.log('Success', data);
        // Redirect to update form page
        window.location.href = '/update';
    })
}