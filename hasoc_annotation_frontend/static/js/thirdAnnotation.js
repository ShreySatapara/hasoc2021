proxy = 'http://127.0.0.1:5000';
//proxy = 'http://127.0.0.1:5000/'
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
        body.style.display = 'block';
        //localStorage.setItem('name', d.name);
        //document.getElementById('user_name').innerHTML = localStorage.getItem('name');
        displayTweetForAnnotate();
    }
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

/*async function checkLogin() {
    let email = localStorage.getItem('email');
    let password = localStorage.getItem('password');
    var body = document.getElementById("body")

    body.style.display = 'none';
    var current_url = window.location.href;
    //let adminAccess = localStorage.getItem('isAdmin');
    url = proxy + '/login'
    var data = await fetch(url, {
        method: 'post',
        body: JSON.stringify({
            'email': email,
            'password': password,
            'isadmin': false
        }),
        headers: {
            'Content-type': 'application/json'
        }
    })

    if (data.status === 200) {
        d = await data.json();
        body.style.display = 'block';
        localStorage.setItem('name', d.name);
        document.getElementById('user_name').innerHTML = localStorage.getItem('name');
        displayTweetForAnnotate();
    } else {
        //console.log(d)
        console.log('imin')
        window.location.href = proxy + '/login';
    }
}*/


async function displayTweetForAnnotate(tweet_id) {
    //document.getElementById("submitlabels").style.display = 'block';
    var name = localStorage.getItem('name')
    document.getElementById("user_name").innerHTML = "Welcome, " + name;
    const response = await fetch(proxy + '/tweet_for_third_annotation/' + name + '/' + tweet_id, {
        headers: {
            "x-access-token": localStorage.getItem("token")
        }
    })
    if (response.status === 200) {
        var data = await response.json();
        data = data['tweet']
        console.log(data)
        labels = data[name]
        document.getElementById('main_tweet_id').value = data.tweet_id;
        localStorage.setItem('tweet_id', data.tweet_id)
        tab_1 = ``
        labels_1 = data[data['annotated_by'][0]]
        labels_2 = data[data['annotated_by'][1]]
        console.log(labels_1)
        console.log(labels_2)
        prev_annotated_tweets = labels_2

        /////////
        if (labels_1[data.tweet_id] === labels_2[data.tweet_id]) {
            label = labels_1[data.tweet_id]
            if (label === "HOF") {
                innerhtml = `<label class="btn btn-danger form-check-label mr-3">HOF</label>`
            } else {
                innerhtml = `<label class="btn btn-success form-check-label mr-3">NONE</label>`
            }
            tab_1 += `<li class="list-group-item d-flex justify-content-between align-items-center input-group-prepend list-group-item-primary">
            <span class="w-90" id="main_tweet" >${data.tweet}</span><div class="btn-group" data-toggle="buttons">` + innerhtml + `</div></li>`
        } else {
            if (data.tweet_id in labels) {
                label = labels[data.tweet_id]
                if (label === "HOF") {
                    innerhtml = `<i class="mr-3 fa fa-check" aria-hidden="true"></i><label class="btn btn-danger form-check-label mr-3">
                <input class="form-check-input" onchange="addLabel(this.name,this.value)" type="radio" name="${data.tweet_id}" value="HOF" checked>
                HOF
              </label>
                  <label class="btn btn-success form-check-label">
                <input class="form-check-input" onchange="addLabel(this.name,this.value)" type="radio" name="${data.tweet_id}" value="NONE"> NONE
              </label>`
                } else {
                    innerhtml = `<label class="btn btn-danger form-check-label mr-3">
                <input class="form-check-input" onchange="addLabel(this.name,this.value)" type="radio" name="${data.tweet_id}" value="HOF">
                HOF
              </label>
                  <label class="btn btn-success form-check-label">
                <input class="form-check-input" onchange="addLabel(this.name,this.value)" type="radio" name="${data.tweet_id}" value="NONE" checked> NONE
              </label>`
                }
                tab_1 += `<li class="list-group-item d-flex justify-content-between align-items-center input-group-prepend list-group-item-primary">
                <span class="w-90" id="main_tweet" >${data.tweet}</span><div class="btn-group" data-toggle="buttons">` + innerhtml + `</div></li>`
            } else {
                tab_1 += `<li class="list-group-item d-flex justify-content-between align-items-center input-group-prepend list-group-item-primary">
            <span class="w-90" id="main_tweet" >${data.tweet}</span>
            <div class="btn-group" data-toggle="buttons">
            <label class="btn btn-danger form-check-label mr-3">
            <input class="form-check-input" onchange="addLabel(this.name,this.value)" type="radio" name="${data.tweet_id}" value="HOF">
            HOF
            </label>
            <label class="btn btn-success form-check-label">
            <input class="form-check-input" onchange="addLabel(this.name,this.value)" type="radio" name="${data.tweet_id}" value="NONE"> NONE
            </label>
            </div>
            </li>`
            }
        }
        document.getElementById('top_tweet').innerHTML = tab_1;
        tab = ``
        for (comm_key in data.comments) {
            comm_tweet_id = data.comments[comm_key].tweet_id;
            if (comm_tweet_id in prev_annotated_tweets) {
                if (labels_1[comm_tweet_id] === labels_2[comm_tweet_id]) {
                    label = labels_1[comm_tweet_id]
                    if (label === "HOF") {
                        innerhtml = `<label class="btn btn-danger form-check-label mr-3">HOF</label>`
                    } else {
                        innerhtml = `<label class="btn btn-success form-check-label mr-3">NONE</label>`
                    }
                    tab += `<li class="list-group-item d-flex justify-content-between align-items-center input-group-prepend list-group-item-secondary">
                        <span class="comment w-90" id="main_tweet" >${data.comments[comm_key].tweet}</span><div class="btn-group" data-toggle="buttons">` + innerhtml + `</div></li>`
                } else if (comm_tweet_id in labels) {
                    label = labels[comm_tweet_id]
                    if (label === "HOF") {
                        innerhtml = `<i class="mr-3 fa fa-check" aria-hidden="true"></i><label class="btn btn-danger form-check-label mr-3">
                        <input class="form-check-input" onchange="addLabel(this.name,this.value)" type="radio" name="${comm_tweet_id}" value="HOF" checked>
                        HOF
                      </label>
                          <label class="btn btn-success form-check-label">
                        <input class="form-check-input" onchange="addLabel(this.name,this.value)" type="radio" name="${comm_tweet_id}" value="NONE"> NONE
                      </label>`
                    } else {
                        innerhtml = `<i class="mr-3 fa fa-check" aria-hidden="true"></i><label class="btn btn-danger form-check-label mr-3">
                        <input class="form-check-input" onchange="addLabel(this.name,this.value)" type="radio" name="${comm_tweet_id}" value="HOF">
                        HOF
                      </label>
                          <label class="btn btn-success form-check-label">
                        <input class="form-check-input" onchange="addLabel(this.name,this.value)" type="radio" name="${comm_tweet_id}" value="NONE" checked> NONE
                      </label>`
                    }
                    tab += `<div class="mb-3"><li class="list-group-item d-flex justify-content-between align-items-center input-group-prepend comment list-group-item-secondary">
                    <span class="comment w-90">${data.comments[comm_key].tweet}</span><div class="btn-group " data-toggle="buttons">` + innerhtml + `</div></li>`
                } else {
                    tab += `<div class="mb-3"><li class="list-group-item d-flex justify-content-between align-items-center input-group-prepend comment list-group-item-secondary">
                    <span class="comment w-90">${data.comments[comm_key].tweet}</span>
                    <div class="btn-group comm" data-toggle="buttons">
                        <label class="btn btn-danger form-check-label mr-3">
                  <input class="form-check-input mr-2" onchange="addLabel(this.name,this.value)" type="radio" name="${comm_tweet_id}" value="HOF" autocomplete="off">
                  HOF
                </label>
                        <label class="btn btn-success form-check-label">
                  <input class="form-check-input" onchange="addLabel(this.name,this.value)" type="radio" name="${comm_tweet_id}" value="NONE" autocomplete="off"> NONE
                </label>
                    </div>
                </li>`
                }
                for (rep_key in data.comments[comm_key].replies) {
                    rep_tweet_id = data.comments[comm_key].replies[rep_key].tweet_id;
                    if (rep_tweet_id in prev_annotated_tweets) {
                        if (labels_1[rep_tweet_id] === labels_2[rep_tweet_id]) {
                            label = labels_1[rep_tweet_id]
                            if (label === "HOF") {
                                innerhtml = `<label class="btn btn-danger form-check-label mr-3">HOF</label>`
                            } else {
                                innerhtml = `<label class="btn btn-success form-check-label mr-3">NONE</label>`
                            }
                            tab += `<li class="list-group-item d-flex justify-content-between align-items-center input-group-prepend list-group-item-success">
                                <span class="reply w-90" id="main_tweet" >${data.comments[comm_key].replies[rep_key].tweet}</span><div class="btn-group" data-toggle="buttons">` + innerhtml + `</div></li>`
                        } else if (rep_tweet_id in labels) {
                            label = labels[rep_tweet_id]
                            if (label === "HOF") {
                                innerhtml = `<i class="mr-3 fa fa-check" aria-hidden="true"></i><label class="btn btn-danger form-check-label mr-3">
                                <input class="form-check-input" onchange="addLabel(this.name,this.value)" type="radio" name="${rep_tweet_id}" value="HOF" checked>
                                HOF
                              </label>
                                  <label class="btn btn-success form-check-label">
                                <input class="form-check-input" onchange="addLabel(this.name,this.value)" type="radio" name="${rep_tweet_id}" value="NONE"> NONE
                              </label>`
                            } else {
                                innerhtml = `<i class="mr-3 fa fa-check" aria-hidden="true"></i><label class="btn btn-danger form-check-label mr-3">
                                <input class="form-check-input" onchange="addLabel(this.name,this.value)" type="radio" name="${rep_tweet_id}" value="HOF">
                                HOF
                              </label>
                                  <label class="btn btn-success form-check-label">
                                <input class="form-check-input" onchange="addLabel(this.name,this.value)" type="radio" name="${rep_tweet_id}" value="NONE" checked> NONE
                              </label>`
                            }
                            tab += `<li class="list-group-item d-flex justify-content-between align-items-center input-group-prepend list-group-item-success">
                                <span class="reply w-90">${data.comments[comm_key].replies[rep_key].tweet}</span><div class="btn-group" data-toggle="buttons">` + innerhtml + `</div></li>`
                        } else {
                            tab += `<li class="list-group-item d-flex justify-content-between align-items-center input-group-prepend list-group-item-success">
                                    <span class="reply w-90">${data.comments[comm_key].replies[rep_key].tweet}</span>
                                    <div class="btn-group" data-toggle="buttons">
                                    <label class="btn btn-danger form-check-label mr-3">
                                <input class="form-check-input" onchange="addLabel(this.name,this.value)" type="radio" name="${rep_tweet_id}" value="HOF" autocomplete="off">
                                    HOF
                                </label>
                                <label class="btn btn-success form-check-label">
                                <input class="form-check-input" onchange="addLabel(this.name,this.value)" type="radio" name="${rep_tweet_id}" value="NONE" autocomplete="off"> NONE
                                </label>
                                </div>
                                </li>`
                        }

                        tab += `</div>`
                    }


                }
            }

        }
        document.getElementById("comments_replies").innerHTML = tab;
        //document.getElementById('display_count').innerHTML = 'Tweets annotated: ' + count;
        //document.getElementById('display_count').value = count;
        /////////

    } else if (response.status == 401) {
        window.location.href = 'login.html';
    } else if (response.status == 404) {
        Swal.fire({
            title: 'Good Job! No tweets to annotate',
            icon: 'success',
        })
        document.getElementById("submitlabels").style.display = 'none';
        $('tweets_by_user').modal('show');
    }
}


function logout() {
    localStorage.clear();
    window.location.href = 'login.html';
}



async function display_tweets_by_user() {
    let name = localStorage.getItem('name');
    url = proxy + '/api/tweet_by_user?name=' + name
    let response = await fetch(url, {
        headers: {
            "x-access-token": localStorage.getItem("token")
        }
    })
    if (response.status === 200) {
        var data = await response.json();
        data = data.data
            //onsole.log(data)
        if (data.length === 0) {
            tab = `<h1 class="my-3">No Assigned Tweets.......!</h1>`
        } else {
            //console.log(data)
            tab = ``

            for (key in data) {
                assigned_to = data[key].assigned_to
                if (assigned_to.length === 3) {
                    if (assigned_to[2] === name) {
                        tab += `<tr>
            <td class="align-middle">${data[key].story}</td>
            <td class="align-middle">${data[key].tweet_id}</td>
            <td class="align-middle">${data[key].tweet}</td>
            <td class="align-middle">
                <div class=" container justify-content-center">`

                        if (data[key].annotated_by.includes(name)) {
                            icon = `<i class="fas fa-check-circle mr-3 fa-2x">`
                            btn = `</i></div></td>
            <td class="align-middle"><button class="btn btn-info" id="${data[key].tweet_id}" onclick="displayTweetForAnnotate(this.id)" data-dismiss="modal">View</button></td>
            </tr>`
                        } else {
                            icon = `<i class="fas fa-clock fa-2x"></i>`

                            btn = `</i></div></td>
                    <td class="align-middle"><button class="btn btn-info" id="${data[key].tweet_id}" onclick="displayTweetForAnnotate(this.id)" data-dismiss="modal">Annotate</button></td>
                </tr>`
                        }
                        tab += icon
                        tab += btn
                    }
                }
            }

        }
        document.getElementById("show_tweets_for_user").innerHTML = tab;
        $('tweets_by_user').modal('show');
    } else if (response.status == 401) {
        window.location.href = 'login.html';
    }

}


/*async function postData() {
    console.log('imin')
    var formElements = document.getElementById("labels_form").elements;
    var postData = {};
    for (var i = 0; i < formElements.length; i++)
        if (formElements[i].type === "radio") {
            if (formElements[i].checked) {
                postData[formElements[i].name] = formElements[i].value;
            }
        }
        //we dont want to include the submit-buttom
    let tweet_id = formElements[0].name;
    let name = localStorage.getItem('name');
    let response = await fetch(proxy + '/tweet_for_annotation/' + name + '/' + tweet_id, {
        method: 'post',
        body: JSON.stringify({
            'labels': postData
        }),
        headers: {
            "x-access-token": localStorage.getItem("token"),
            'Content-type': 'application/json'
        }
    });
    if (response.status === 200) {
        displayTweetForAnnotate();

    } else {
        Swal.fire({
            title: 'Error Occured! try again',
            icon: 'error',
            timer: 1800
        })
    }

}*/

async function changePassword() {
    var name = localStorage.getItem('name')
        //var token = document.getElementById('token')
    Swal.fire({
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
                        window.location.href = 'login.html';
                    } else {
                        Swal.showValidationMessage(`Password and confirm password does not match`)
                    }
                })
            }
        }
    })
}


async function addLabel(id, label) {
    console.log(id + ' ' + label)
        //var formElements = document.getElementById("labels_form").elements;
    var tweet_id = document.getElementById("main_tweet_id").value;
    console.log(tweet_id); //localStorage.getItem('tweet_id')
    let name = localStorage.getItem('name')
        //console.log(tweet_id)
    $.ajax({
        type: 'POST',
        url: proxy + '/tweet_for_annotation/' + name + '/' + tweet_id,
        //contentType: "application/json; charset=utf-8",  
        //dataType: 'json',  
        headers: {
            "x-access-token": localStorage.getItem("token"),
            'Content-type': 'application/json'
        },
        data: JSON.stringify({ 'id': id, 'label': label }),
        async: true,
        success: function(response) {
            myparent = $('[name=' + id + ']').parent().parent();
            //console.log(myparent)
            if (label == "HOF") {
                innerhtml = `<i class="mr-3 fa fa-check" aria-hidden="true"></i> <label class="btn btn-danger form-check-label mr-3">
            <input class="form-check-input" onchange="addLabel(this.name,this.value)" type="radio" name="${id}" value="HOF" checked>
            HOF
          </label>
              <label class="btn btn-success form-check-label">
            <input class="form-check-input" onchange="addLabel(this.name,this.value)" type="radio" name="${id}" value="NONE"> NONE
          </label>`
            } else {
                innerhtml = `<i class="mr-3 fa fa-check" aria-hidden="true"></i> <label class="btn btn-danger form-check-label mr-3">
            <input class="form-check-input" onchange="addLabel(this.name,this.value)" type="radio" name="${id}" value="HOF">
            HOF
          </label>
              <label class="btn btn-success form-check-label">
            <input class="form-check-input" onchange="addLabel(this.name,this.value)" type="radio" name="${id}" value="NONE" checked> NONE
          </label>`
            }
            myparent.html(innerhtml)
        },
        error: function(XMLHttpRequest, textStatus, errorThrown) {
            alert('error');
        }
    });
}