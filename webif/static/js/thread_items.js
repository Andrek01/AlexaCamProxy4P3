var user = ""
var pwd = ""
//*******************************************
// Button Handler committing changes
//*******************************************

function CommitValues(result)
{
      VideoBuffer = document.getElementById("txtVideoBuffer").value;
      authorization_1 = document.getElementById("authorization_1").value;

	$.ajax({
		url: "commit.html",
		type: "GET",
		data: { 
		           	VideoBuffer : VideoBuffer,
			        authorization_1 : authorization_1
		      },
		contentType: "application/json; charset=utf-8",
		success: function (response) {
				ValidateResponse(response);
		},
		error: function () {
			document.getElementById("txt_Result").innerHTML = "Error while Communication !";
		}
	});
  return
}

//*************************************************************
// ValidateResponse -checks the commitment of the settings
//*************************************************************

function ValidateResponse(response)
{
var myResult = ""
var temp = ""
var objResponse = JSON.parse(response)
for (x in objResponse)
    {
         if (x == "0")
     	{
            document.getElementById("actAuthorization").textContent = authorization_1;	        
	    }
         else
	    {
	      temp = temp + objResponse[x]+"\n";
	    }
    }

document.getElementById("txt_Result").value = temp;
}

//*************************************************************
// ValidateEncodeResponse -checks the login-button
//*************************************************************

function ValidateEncodeResponse(response)
{
var myResult = ""
var temp = ""
var objResponse = JSON.parse(response)
for (x in objResponse)
    {
     if (x == "0")
 	{
	  document.getElementById("txtEncoded").value = objResponse[x].substr(8);	  
	}
     else
	{
	  temp = temp + objResponse[x]+"\n";
	}
    }

document.getElementById("txt_Result").value = temp;
if (document.getElementById("store_2_config").checked == true)
 {
    document.getElementById("proxyCredentials").textContent = user+":"+pwd;
  }

}

//*******************************************
// Button Handler for Encoding credentials
//*******************************************

function BtnEncode(result)
{
      user = document.getElementById("txtUser").value;
      pwd = document.getElementById("txtPwd").value;
      store2config = document.getElementById("store_2_config").checked;
      encoded=user+":"+pwd;
      encoded=btoa(encoded);
      //document.getElementById("txtEncoded").value = encoded;
	$.ajax({
		url: "store_credentials.html",
		type: "GET",
		data: { encoded : encoded,
			user : user,
		   	pwd : pwd,
			store_2_config : store2config
		      },
		contentType: "application/json; charset=utf-8",
		success: function (response) {
				ValidateEncodeResponse(response);
		},
		error: function () {
			document.getElementById("txt_Result").innerHTML = "Error while Communication !";
		}
	});
  return
}

//*************************************************************
// check Auto-Updates for protocols
//*************************************************************
setInterval(Checkupdate4Protocolls, 2000);


//*************************************************************
// delete protocol
//*************************************************************

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

//*************************************************************
// resize the Thread-Tables
//*************************************************************
function resizeItemTree() {
    var browserHeight = window.innerHeight;
    offsetTop = $('#threads').offset().top;
    offsetTopDetail = $('#thread_details').offset().top;
    //$('#threads').css("maxHeight", ((-1)*(offsetTop) - 35 + browserHeight)+ 'px');
    $('#threads').css("cssText","overflow: auto scroll; max-height: 1000px;")
    //$('#thread_details').css("maxHeight", ((-1)*(offsetTopDetail) - 35 + browserHeight)+ 'px');
    $('#thread_details').css("cssText","overflow: auto scroll; max-height: 1000px;")
}
resizeItemTree();
//*************************************************************
// update the Thread tables
//*************************************************************
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

//*************************************************************
// reload Threads
//*************************************************************
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

//*************************************************************
// show Thread details
//*************************************************************

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


}window.addEventListener("resize", resizeItemTree, false);
