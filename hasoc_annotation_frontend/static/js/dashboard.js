async function display() {
    $("#LoadingImage").show();
    $('#story_table').hide();
    $.ajax({
        type: 'GET',
        url: proxy + '/admin/dashboard',
        headers: {
            "x-access-token": localStorage.getItem("token"),
            'Content-type': 'application/json'
        },
        async: true,
        success: function(response) {

            storywise_count = response['storywise_count']
            userwise_count = response['userwise_count']
            total_status = response['total_status']
            total_annotated_count = response['total_annotated_count']
            total_tweets_annotated = response['total_tweets_annotated']
            total_tweets_story = response['total_tweets_story']
                //annotated_total = response['annotated_total']
                //assigned_total = response['assigned_total']
            console.log(response);


            story_table_str = ``;
            for (story in storywise_count) {
                //console.log(storywise_count[story].no_of_status)
                story_table_str += `<tr><td>${story}</td>
                <td class="text-center">${storywise_count[story].no_of_status}</td>
                <td class="text-center">${storywise_count[story].tweets_count}</td>
                <td class="text-center">${storywise_count[story].annotated_by_one}</td>
                <td class="text-center">${storywise_count[story].annotated_by_two}</td>
                <td class="text-center">${storywise_count[story].annotated_by_three}</td></tr>`
            }
            story_table_str += `<tr>
                <th>TOTAL</td>
                <th class="text-center">${total_status}</th>
                <th class="text-center">${total_tweets_story}</th>
                <th class="text-center">${total_annotated_count.by_one}</th>
                <th class="text-center">${total_annotated_count.by_two}</th>
                <th class="text-center">${total_annotated_count.by_three}</th>
            </tr>`
            document.getElementById('story_table_body').innerHTML = story_table_str;


            user_table_str = ``
            for (user in userwise_count) {
                if (user !== 'assigned_total' && user !== 'annotated_total') {
                    console.log(userwise_count[user].assigned)
                    user_table_str += `<tr><td>${user}</td>
                <td class="text-center">${userwise_count[user].assigned}</td>
                <td class="text-center">${userwise_count[user].annotated}</td>
                <td class="text-center">${userwise_count[user].tweets_annotated_count}</td></tr>`
                }

            }
            console.log(userwise_count.assigned_total)
            user_table_str += `<tr>
            <th>TOTAL</td>
                <th class="text-center">${userwise_count.assigned_total}</th>
                <th class="text-center">${userwise_count.annotated_total}</th>
                <th class="text-center">${total_tweets_annotated}</th>
        </tr>`
            document.getElementById('user_table_body').innerHTML = user_table_str;

            $("#LoadingImage").hide();
            $('#story_table').show();
        },
        error: function(XMLHttpRequest, textStatus, errorThrown) {
            alert('error');
        }
    });
}