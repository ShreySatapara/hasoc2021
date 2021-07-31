proxy = 'http://127.0.0.1:5000';

async function performLogin() {
    //preventDefault()
    var name = document.getElementById('name').value;
    var password = document.getElementById('password').value;
    var isAdmin = document.getElementById('isAdmin').checked;
    //console.log(isAdmin)
    var response = await fetch(proxy + '/login', {
        method: 'post',
        body: JSON.stringify({
            'name': name,
            'password': password,
            'isadmin': isAdmin
        }),
        headers: {
            'Content-type': 'application/json'
        }
    })

    if (response.status === 201) {
        var data = await response.json()
        var token = data.token
        localStorage.setItem("token", token)
        localStorage.setItem('name', name)
        localStorage.setItem('password', password);
        localStorage.setItem('isAdmin', isAdmin);
        if (isAdmin) {
            //console.log(name + +'is admin')
            window.location.href = 'admin.html';
        } else {
            //console.log(name + 'is user')
            window.location.href = 'index.html';
        }
    } else if (response.status === 404) {
        Swal.fire({
            title: 'Username Does not exist',
            icon: 'error',
        })
    } else if (response.status === 401) {
        Swal.fire({
            title: 'You are not admin, behaviour will be reported',
            icon: 'warning',
        })
    } else if (response.status === 402) {
        Swal.fire({
            title: 'Opps! Incorrect Password, try again....',
            icon: 'error',
        })
    } else if (response.status === 400) {
        Swal.fire({
            title: 'Bad Request',
            icon: 'error',
        })
    } else {
        Swal.fire({
            title: 'Internal server error, please try again later',
            icon: 'error',
        })
    }
}