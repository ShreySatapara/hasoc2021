proxy = 'http://127.0.0.1:5000';

async function checkLogin() {
    var name = localStorage.getItem('name');
    //let password = localStorage.getItem('password');
    //let isAdmin = localStorage.getItem('isAdmin');

    var body = document.getElementById("body");
    body.style.display = 'none';
    url = proxy + '/login'
    var token = document.getElementById("token");
    if (typeof token === "undefined") {
        window.location.href = 'login.html';
    } else {
        //
        if (localStorage.getItem('isAdmin') === "true") {
            body.style.display = 'block';
        } else {
            window.location.href = 'login.html';
        }
        //localStorage.setItem('name', d.name);
    }
    document.getElementById("username").innerHTML = "Welcome, " + name;
    /*var response = await fetch(url, {
        method: 'post',
        body: JSON.stringify({
            'email': email,
            'password': password,
            'isadmin': isAdmin
        }),
        headers: {
            'Content-type': 'application/json'
        }
    })
    if (response.status === 200) {
        d = await response.json();
        localStorage.setItem('name', d.name);
        body.style.display = 'block';
        //localStorage.setItem('name', d.name);
        document.getElementById("username").innerHTML = "Welcome, " + d.name
    } else {
        //console.log(d)
        console.log('imin')

    }*/
}

function logout() {
    window.location.href = 'login.html';
    localStorage.clear();
}

async function changePassword() {
    var name = localStorage.getItem('name')
        //var token = document.getElementById('token')
    Swal.fire({
        title: 'Login Form',
        html: `<input type="password" id="opassword" class="swal2-input" placeholder="current password">
        <input type="password" id="password" class="swal2-input" placeholder="new password">
        <input type="password" id="cpassword" class="swal2-input" placeholder="confirm password">`,
        confirmButtonText: 'Update',
        focusConfirm: false,
        preConfirm: () => {
            const oldpassword = Swal.getPopup().querySelector('#opassword').value;
            const new_password = Swal.getPopup().querySelector('#password').value;
            const c_password = Swal.getPopup().querySelector('#cpassword').value;
            if (!oldpassword || !new_password || !c_password) {
                Swal.showValidationMessage(`Please enter all the fields`)
            }
            if (new_password === c_password) {
                return fetch(proxy + '/change_password', {
                    method: 'post',
                    body: JSON.stringify({
                        'name': name,
                        'password': oldpassword,
                        'new_password': new_password
                    }),
                    headers: {
                        'Content-type': 'application/json',
                        "x-access-token": localStorage.getItem("token")
                    }
                }).then(response => {
                    if (response.status === 200) {
                        Swal.fire({
                            title: 'password updated successfully',
                            icon: 'success',
                            timer: 2000
                        })
                    } else if (response.status === 404) {
                        Swal.showValidationMessage(`User Does not exist`)
                    } else if (response.status === 402) {
                        Swal.showValidationMessage(`Incorrect current password`)
                    } else if (response.status === 401) {
                        window.location.href = 'login.html'
                    } else {
                        Swal.showValidationMessage(`Password and confirm password does not match`)
                    }
                })
            }
        }
    })
}