proxy = 'https://hasocs3-2021-316110.et.r.appspot.com';

async function add_user() {
    Swal.fire({
        title: 'Create User',
        html: `<input type="name" id="name" class="swal2-input" placeholder="username">
        <input type="email" id="Email" class="swal2-input" placeholder="Email">
        <input type="password" id="password" class="swal2-input" placeholder="Password"><br><br>
        <input type="checkbox" id="isadmin" class="mr-3" placeholder="admin access">admin access`,
        confirmButtonText: 'Create',
        focusConfirm: false,
        preConfirm: () => {
            const name = Swal.getPopup().querySelector('#name').value;
            const email = Swal.getPopup().querySelector('#Email').value;
            const password = Swal.getPopup().querySelector('#password').value;
            const isadmin = Swal.getPopup().querySelector('#isadmin').checked;
            //console.log(isadmin)
            return fetch(proxy + `/admin/user`, {
                    method: 'post',
                    body: JSON.stringify({ 'name': name, 'email': email, 'password': password, 'isadmin': isadmin }),
                    headers: {
                        'Content-type': 'application/json',
                        "x-access-token": localStorage.getItem("token")
                    }

                })
                .then(response => {
                    //console.log(response)
                    if (response.status != 200) {
                        throw new Error(response.statusText)
                    }
                    return response.json()
                })
                .catch(error => {
                    Swal.showValidationMessage(
                        `Request failed: ${error}`
                    )
                })
        },
        allowOutsideClick: () => !Swal.isLoading()
    }).then((result) => {
        if (result.isConfirmed) {
            Swal.fire({
                title: 'User Created Successfully!',
                icon: 'success',
                timer: 2000,
                showConfirmButton: false
            })
            display_users();
        }
    })
}


async function display_users() {
    //console.log('in user function');
    url = proxy + '/admin/user';
    const response = await fetch(url, {
        headers: {
            "x-access-token": localStorage.getItem("token")
        }
    });
    if (response.status == 200) {
        var data = await response.json();
        data = data['users'];
        let tab = ''

        //console.log(data)
        for (usr in data) {
            //console.log(data[usr].adminAccess)
            if (data[usr].adminAccess === true) {
                icon = '<i class="fas fa-user-cog mr-3"></i>'
            } else {
                icon = '<i class="fas fa-user mr-3"></i>'
            }
            //icon = '<i class="fas fa-user-cog"></i>'
            tab += `<tr class="candidates-list">
            <td class="title">
                <div class="candidate-list-details">
                    <div class="candidate-list-info align-middle">
                        <div class="candidate-list-title">
                            <h5 class="mb-0 text-primary">${data[usr]._id}</h5>
                        </div>
                        <div class="candidate-list-option">
                            <ul class="list-unstyled">
                                <li>${icon}</i>${data[usr].email}</li>
                            </ul>
                        </div>
                    </div>
                </div>
            </td>
            <td class="candidate-list-favourite-time text-center align-middle">
                <span class="candidate-list-time order-1"><h4>${[data[usr].assigned]}</h4></span>
            </td>
            <td class="candidate-list-favourite-time text-center align-middle">
                <span class="candidate-list-time order-1"><h4>${data[usr].annotated}</h4></span>
            </td>
            <td class="align-middle">
                <div class="list-unstyled mb-0 d-flex justify-content-center">
                    <button href="#" class="btn btn-outline-info" data-toggle="modal" data-target="#assign_tweets" data-toggle="tooltip" data-placement="top" title="Tap to assign tweets to user" id="${data[usr]._id}" onclick="display_tweets_by_users(this.id)">View Report</button>
                </div>
            </td>
        </tr>`
        }
        document.getElementById("user_table").innerHTML = tab;
        //console.log('displaying');
    }
}


async function display_tweets_by_users(name) {
    url = proxy + '/api/tweet_by_user?name=' + name
    let response = await fetch(url, {
        headers: {
            "x-access-token": localStorage.getItem("token")
        }
    })
    if (response.status === 200) {
        var data = await response.json();
        data = data.data
            //console.log(data)
        if (data.length === 0) {
            tab = `<h1 class="my-3">No Assigned Tweets.......!</h1>`
        } else {
            //console.log(data)
            tab = ``
            for (key in data) {
                tab += `<tr>
            <td class="align-middle">${data[key].story}</td>
            <td class="align-middle">${data[key].tweet_id}</td>
            <td class="align-middle">${data[key].tweet}</td>
            <td class="align-middle">
                <div class=" container justify-content-center">`

                if (data[key].annotated_by.includes(name)) {
                    icon = `<i class="fas fa-check-circle mr-3 fa-2x">`
                } else { icon = `<i class="fas fa-clock fa-2x"></i>` }
                tab += icon
                tab += `</i></div></td>
            <td class="align-middle"><button class="btn btn-info" disabled>View</button></td>
        </tr>`
            }

        }
        document.getElementById("show_tweets_for_user").innerHTML = tab;
    }

}