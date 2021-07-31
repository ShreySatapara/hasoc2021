proxy = 'http://127.0.0.1:5000';

async function show_tweets_index() {
    url = proxy + '/admin/story?count_required=0';
    const response = await fetch(url, {
        headers: {
            "x-access-token": localStorage.getItem("token")
        }
    });
    filter_list_options = `<option value="" selected hidden>Sort By: Story</option><option value="all">All</option>`
    if (response.status === 200) {
        var data = await response.json();
        stories = data['stories'];
        //console.log(stories)
        for (key in stories) {
            filter_list_options += `<option value="${stories[key]._id}">${stories[key]._id}</option>`
        }
    } else if (response.status === 401) {
        window.location.href = 'login.html'
    }
    document.getElementById("filter_story_list").innerHTML = filter_list_options;

    story_name = document.getElementById('')
    url = proxy + '/api/index'
    const responce = await fetch(url, {
        headers: {
            "x-access-token": localStorage.getItem("token")
        }
    });
    data = await responce.json();
    //console.log(data)
    if (responce.status === 200) {
        tweet_data = data['tweet_data'];
        users = data['users'];
        //console.log(tweet_data)
        //console.log(users);
        //console.log(tweet_data)
        let tab = '';
        for (key in tweet_data) {
            form_id = 'form_' + tweet_data[key].tweet_id;
            tab += `<form id="${form_id}"><tr>
            <th scope="row" class="align-middle">${tweet_data[key].story}</th>
            <td class="align-middle">${tweet_data[key].tweet_id}</td>
            <td class="w-50" class="align-middle">${tweet_data[key].tweet}</td>`
            assigned_to = tweet_data[key].assigned_to;
            list_for_select = []
            for (usr in users) {
                if (!(assigned_to.includes(users[usr]._id))) {
                    list_for_select.push({ 'name': users[usr]._id });
                }
            }
            //console.log(list_for_select);
            count = 0;
            for (u in assigned_to) {
                if (tweet_data[key].annotated_by.includes(assigned_to[u])) {
                    tab += `<td class="align-middle text-success"><i class="fas fa-check-circle mr-1"></i>${assigned_to[u]}</td>`
                } else {
                    tab += `<td class="align-middle text-danger"><i class="fas fa-clock mr-1"></i>${assigned_to[u]}</td>`
                }
                count += 1;
            }
            select_options = '';
            for (k in list_for_select) {
                select_options += `<option value="${list_for_select[k].name}">${list_for_select[k].name}</option>`
            }

            if (assigned_to.length < 3) {
                while (count < 3) {
                    tab += `<td class="align-middle"><select form="${form_id}" class="form-select" name="${count}" aria-label="Default select example">
                    <option selected hidden>Select User</option>${select_options}</select></td>`
                    count += 1
                }
                tab += `<td class="align-middle"><button type="submit" class="btn btn-outline-primary" id="${tweet_data[key].tweet_id}" onclick="assign_users(this.id)">ASSIGN</button></td></tr></form>`
            } else {
                tab += `<td class="align-middle"></td></tr></form>`
            }


        }
        document.getElementById('tweet_data_body').innerHTML = tab;
    } else {
        document.getElementById('tweet_data_body').innerHTML = `<h1 class="mt-5">No Tweets Found</h1>`;
    }

}

async function assign_users(id) {
    var formElements = document.getElementById("form_" + id).elements;
    userList = []
    for (var i = 0; i < formElements.length; i++) {
        if (formElements[i].type != "submit") //we dont want to include the submit-buttom
            userList.push(formElements[i].value);
    }
    let filtered_userList = filtered = userList.filter(function(str) { return !str.includes('Select User'); });
    userSet = new Set(filtered_userList)
    if (filtered_userList.length === userSet.size) {
        fetch(proxy + '/api/index', {
            method: 'post',
            body: JSON.stringify({ 'tweet_id': id, 'users_assigned': filtered_userList }),
            headers: {
                'Content-type': 'application/json',
                "x-access-token": localStorage.getItem("token")
            }
        }).then(responce => {
            if (responce.status === 200) {
                Swal.fire({
                    title: 'Tweet Assigned Successfully!',
                    icon: 'success',
                    timer: 2000
                })
                show_tweets_index();
            } else if (responce.status === 401) {
                window.location.href = 'login.html';
            }
        })
    } else {
        alert('cannot be same')
    }

}


///// show stories

async function showStories() {
    const url = proxy + '/admin/story?count_required=1';
    const response = await fetch(url, {
        headers: {
            "x-access-token": localStorage.getItem("token")
        }
    });
    tab = '';
    filter_list_options = `<select class="col-3 form-select form-select-lg"><option value="all" selected>Sort By: Story</option>`
    if (response.status === 200) {
        var data = await response.json();
        stories = data['stories'];
        counts = data['count']
            //console.log(counts)
            //console.log(stories)
        for (key in stories) {
            story_name = stories[key]._id
                //console.log(counts[story_name])
                //console.log(key)

            //console.log(stories[key]._id)
            tab += `<li class="list-group-item d-flex justify-content-between align-items-center">
            ${story_name}
            <span class="badge badge-primary badge-pill">${counts[story_name]}</span></li>`

            ////////////////////////////////////
            filter_list_options += `<option value="${stories[key]._id}">${stories[key]._id}</option>`
        }
        filter_list_options += `</select>`
    }
    document.getElementById("story_list").innerHTML = tab;
    document.getElementById("filter_story_list").innerHTML = filter_list_options;
}



/// ADD story
async function add_story() {
    let story_name = document.getElementById('new_story_name').value;
    if (story_name.length > 0) {
        fetch(proxy + `/admin/story`, {
            method: 'post',
            body: JSON.stringify({ 'story': story_name }),
            headers: {
                'Content-type': 'application/json',
                "x-access-token": localStorage.getItem("token")
            }
        }).then(response => {
            if (response.status === 200) {
                Swal.fire({
                    title: 'Story Added Successfully',
                    icon: 'success',
                    timer: 2000,
                    showConfirmButton: false
                })
                showStories();
                document.getElementById('new_story_name').value = '';
            } else if (response.status === 401) {
                window.location.href = 'login.html';
            } else if (response.status === 403) {
                Swal.fire({
                    title: '! Cannot add same story again !!!',
                    icon: 'warning'
                })
            } else if (response.status === 400) {
                Swal.fire({
                    title: 'Bad Request!!!',
                    icon: 'error'
                })
            } else {
                Swal.fire({
                    title: 'Internal Server Error!!!',
                    icon: 'error'
                })
            }
        })
    } else {
        alert('please enter story name')
    }
}


//////  ADD tweet

async function add_tweets() {
    const url = proxy + '/admin/story?count_required=0';
    const response = await fetch(url, {
        headers: {
            "x-access-token": localStorage.getItem("token")
        }
    });
    if (response.status === 200) {
        var data = await response.json();
        stories = data['stories'];
        //console.log(stories)
        select_option = '<option value="" selected hidden>Select Story</option>'
        for (key in stories) {
            select_option += `<option value="${stories[key]._id}">${stories[key]._id}</option>`
        }
    } else if (response.status === 401) {
        window.location.href = 'login.html'
    } else {
        alert('network error')
    }
    let select_box_html = `<select id="story_name_for_tweet" class="swal2-input">${select_option}</select>`
    Swal.fire({
        title: 'Add Tweet File',
        html: `${select_box_html}<input type="file" id="file" class="swal2-input" placeholder="file" multiple>`,
        confirmButtonText: 'SUBMIT',
        focusConfirm: false,
        preConfirm: () => {
            var input = document.getElementById("file");
            var sel = document.getElementById("story_name_for_tweet")
            var opt = sel.options[sel.selectedIndex];
            let story_name = opt.value;
            if (input.files && input.files[0]) {
                const formData = new FormData();
                for (const file of input.files) {
                    formData.append('files', file)
                }
                //let myFile = input.files[0]
                //formData.append('file', myFile);
                formData.append('story_name', story_name);
                console.log(input.files)
                    //console.log(story_name)
                return fetch(proxy + `/admin/add_tweet`, {
                        method: 'post',
                        body: formData,
                        headers: {
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
            }
        },
        allowOutsideClick: () => !Swal.isLoading()
    }).then((result) => {
        if (result.isConfirmed) {
            Swal.fire({
                title: 'tweet Added Successfully!',
                icon: 'success',
                timer: 2000,
                showConfirmButton: false
            })
            show_tweets_index();
        }
    })
}

////// FIlter Tweets
async function filter_tweets() {
    //console.log('changed')
    var story_name = document.getElementById("filter_story_list").value;
    url = proxy + '/api/index?story_name=' + story_name;
    const responce = await fetch(url, {
        headers: {
            "x-access-token": localStorage.getItem("token")
        }
    });
    data = await responce.json();
    //console.log(data)
    if (responce.status === 200) {
        tweet_data = data['tweet_data'];
        users = data['users'];
        //console.log(tweet_data)
        //console.log(users);
        //console.log(tweet_data)
        let tab = '';
        for (key in tweet_data) {
            form_id = 'form_' + tweet_data[key].tweet_id;
            tab += `<form id="${form_id}"><tr>
            <th scope="row" class="align-middle">${tweet_data[key].story}</th>
            <td class="align-middle">${tweet_data[key].tweet_id}</td>
            <td class="w-50" class="align-middle">${tweet_data[key].tweet}</td>`
            assigned_to = tweet_data[key].assigned_to;
            //console.log(assigned_to)
            list_for_select = []
            for (usr in users) {
                if (!(assigned_to.includes(users[usr]._id))) {
                    list_for_select.push({ 'name': users[usr]._id, 'id': users[usr]._id });
                }
            }
            //console.log(list_for_select);
            count = 0;
            for (u in assigned_to) {
                if (tweet_data[key].annotated_by.includes(assigned_to[u])) {
                    tab += `<td class="align-middle text-success"><i class="fas fa-check-circle mr-1"></i>${assigned_to[u]}</td>`
                } else {
                    tab += `<td class="align-middle text-danger"><i class="fas fa-clock mr-1"></i>${assigned_to[u]}</td>`
                }
                count += 1;
            }
            select_options = '';
            for (k in list_for_select) {
                select_options += `<option value="${list_for_select[k].name}">${list_for_select[k].name}</option>`
            }

            if (assigned_to.length < 3) {
                while (count < 3) {
                    tab += `<td class="align-middle"><select form="${form_id}" class="form-select" name="${count}" aria-label="Default select example">
                    <option selected selected hidden>Select User</option>${select_options}</select></td>`
                    count += 1
                }
                tab += `<td class="align-middle"><button type="submit" class="btn btn-outline-primary" id="${tweet_data[key].tweet_id}" onclick="assign_users(this.id)">ASSIGN</button></td></tr></form>`
            } else {
                tab += `<td class="align-middle"></td></tr></form>`
            }


        }
        document.getElementById('tweet_data_body').innerHTML = tab;
    } else {
        document.getElementById('tweet_data_body').innerHTML = `<h1 class="mt-5">No Tweets Found</h1>`;
    }
}