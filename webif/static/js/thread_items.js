window.addEventListener("resize", resizeItemTree, false);

//*************************************************************
// check Auto-Updates for protocols
//*************************************************************
setInterval(Checkupdate4Protocolls, 2000);




function DeleteProto(btn_Name)
{
     $.ajax({
    url: "clear_proto.html",
    type: "GET",
    data: { proto_Name : btn_Name
          },
    contentType: "application/json; charset=utf-8",
    success: function (response) {
            statelogCodeMirror.setValue("");
    },
    error: function () {
        console.log("Error - while clearing Protocol :"+btn_Name)
    }
     });
}

//*************************************************************
// check Toggle-Switches
//*************************************************************
function ToggleTrigger(myID) {
 myValue = document.getElementById(myID).checked
 switch (myID) {
	case 'toggleTestSocket':
		{
	    $.ajax({
		    url: "toggle_TestSocket.html",
		    type: "GET",
		    data: { enabled : myValue
		          },
		    contentType: "application/json; charset=utf-8",
		    success: function (response) {
			    console.log("OK - TestSocket-State changed");
		    },
		    error: function () {
                console.log("Error - while changing TestSocket-State")
		    }
	    });
        break;
		}
    }
}


//*************************************************************
// Auto-Update-Timer for protocol - States
//*************************************************************

function UpdateProto(proto_Name)
{
	$.ajax({
		url: "get_proto.html",
		type: "GET",
		data: { proto_Name : proto_Name
		      },
		contentType: "application/json; charset=utf-8",
		success: function (response) {
				actProto(response,proto_Name);
		},
		error: function () {
            console.log("Error - while updating Protocol :"+proto_Name)
		}
	});
};

//*************************************************************
// check Auto-Updates for protocols
//*************************************************************
function Checkupdate4Protocolls()
{ 
    UpdateLog = document.getElementById("proto_states_check").checked

    if (UpdateLog == true)
    {
     UpdateProto('proto_states_check')
    }

}
//*************************************************************
// actualisation of Protocol
//*************************************************************
function actProto(response,proto_Name)
{
    myProto = document.getElementById(proto_Name)
    myProto.value = ""
    myText = ""
    var objResponse = JSON.parse(response)
    for (x in objResponse)
        {
         myText += objResponse[x]+"\n"
        }
    myProto.value = myText
    if (proto_Name == 'proto_states_check')
    {
        statelogCodeMirror.setValue(myText)
    }
}

function resizeItemTree() {
    var browserHeight = $( window ).height();
    offsetTop = $('#threads').offset().top;
    offsetTopDetail = $('#thread_details').offset().top;
    //$('#threads').css("maxHeight", ((-1)*(offsetTop) - 35 + browserHeight)+ 'px');
    //$('#thread_details').css("maxHeight", ((-1)*(offsetTopDetail) - 35 + browserHeight)+ 'px');
}
resizeItemTree();

function BuildThreads(result)
{
    var temp ='';
    temp = '<div class="table-responsive" style="min-width: 500px;"><table class="table table-striped table-hover">';
    temp = temp + '<thead><tr class="shng_heading"><th class="py-1">Thread-Name </th><th class="py-1">Real-URL</th><th align="right" class="py-1" style="text-align:center;" >Status</th></tr></thead>';
    temp = temp + '<tbody>';
	
    $.each(result, function(index, element) {
        temp = temp + '<a href="SelectListItem"><tr><td class="py-1">'+ element.Thread + '</td><td class="py-1">'+ element.real_URL +'</td><td class="py-1" align="center">'+ element.Status +'</td></tr>';
    	        
    })
    temp = temp + '</tbody></table></div>';
    $('#threads').html(temp);
}


function reloadThreads()
{
        $('#refresh-element').addClass('fa-spin');
        $('#reload-element').addClass('fa-spin');
        $('#cardOverlay').show();
        $.getJSON('thread_list_json_html', function(result)
        		{
	        	BuildThreads(result);
	            window.setTimeout(function()
	            		{
		                $('#refresh-element').removeClass('fa-spin');
		                $('#reload-element').removeClass('fa-spin');
		                $('#cardOverlay').hide();
	            		}, 300);

        		});
    
}


function BuildThreadDetails(result)
{
    var temp ='';
    temp = '<div class="table-responsive" style="min-width: 500px;"><table class="table table-striped table-hover">';
    temp = temp + '<thead><tr class="shng_heading"><th class="py-1">Property</th><th class="py-1">Value</th></tr></thead>';
    temp = temp + '<tbody>';
	
    $.each(result, function(index, element) {
        temp = temp + '<tr><td class="py-1">'+ index + '</td><td class="py-1">'+ element +'</td></tr>';
    	        
    })
    temp = temp + '</tbody></table></div>';
    $('#thread_details').html(temp);
}


function SelectListItem(threadname)
{
    $('#refresh-element_details').addClass('fa-spin');
    $('#reload-element_details').addClass('fa-spin');
    $('#cardOverlay_Details').show();
    
    $.getJSON('thread_details_json.html?thread_name='+threadname, function(result)
    		{
    	    BuildThreadDetails(result);
            window.setTimeout(function()
            		{
	                $('#refresh-element_details').removeClass('fa-spin');
	                $('#reload-element_details').removeClass('fa-spin');
	                $('#cardOverlay_Details').hide();
            		}, 10);

    		});


}
