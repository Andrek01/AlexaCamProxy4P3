window.addEventListener("resize", resizeItemTree, false);

function ToggleTrigger(myID) {
 myValue = document.getElementById(myID).checked
 switch (myParam) {
	case 'toggleTestSocket':
		{
			if (myValue == 'True')
			{
			
			}
            else
            {
            }
			break;
		}
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
    temp = temp + '<thead><tr class="shng_heading"><th class="py-1">Thread-Name </th><th class="py-1">Real-URL</th><th align="right" class="py-1" >Status</th></tr></thead>';
    temp = temp + '<tbody>';
	
    $.each(result, function(index, element) {
        temp = temp + '<a href="SelectListItem"><tr><td class="py-1">'+ element.Thread + '</td><td class="py-1">'+ element.real_URL +'</td><td class="py-1">'+ element.real_URL +'</td></tr>';
    	        
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
