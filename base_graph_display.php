<?php
/*******************************************************************************
** Basic Analysis and Security Engine (BASE)
** Copyright (C) 2004 BASE Project Team
** Copyright (C) 2000 Carnegie Mellon University
**
** (see the file 'base_main.php' for license details)
**
** Project Leads: Kevin Johnson <kjohnson@secureideas.net>
** Built upon work by Roman Danyliw <rdd@cert.org>, <roman@danyliw.com>
**
** Purpose: Purpose: Displays the actual .GIF/.PNG/.TIFF image
**          of the chart
**
** Input GET/POST variables
**   - width: chart width
**   - height: chart width
**   - pmargin0-3: plot margins
**   - title: chart title
**   - xaxis_label: x-axis label
**   - yaxis_label: y-axis label
**   - xdata[][]: data and label array for the y-axis
**   - yaxis_scale: (boolean) 0: linear; 1: logarithmic
**   - rotate_xaxis_lbl: (boolean) rotate X-axis labels 90 degrees
**   - style: [bar|line] chooses the style of the chart
********************************************************************************
** Authors:
********************************************************************************
** Kevin Johnson <kjohnson@secureideas.net
**
********************************************************************************
*/

  include ("base_conf.php");
  include ("$BASE_path/includes/base_constants.inc.php");
  include ("$BASE_path/includes/base_state_common.inc.php");
  include ("$BASE_path/base_graph_common.php");
  require_once('Image/Graph.php');

  $xdata = $_SESSION['xdata'];
  $width = ImportHTTPVar("width", VAR_DIGIT);
  $height = ImportHTTPVar("height", VAR_DIGIT);
  $pmargin0 = ImportHTTPVar("pmargin0", VAR_DIGIT);
  $pmargin1 = ImportHTTPVar("pmargin1", VAR_DIGIT);
  $pmargin2 = ImportHTTPVar("pmargin2", VAR_DIGIT);
  $pmargin3 = ImportHTTPVar("pmargin3", VAR_DIGIT);
  $title = ImportHTTPVar("title", VAR_ALPHA | VAR_SPACE);
  $xaxis_label = ImportHTTPVar("xaxis_label", VAR_ALPHA | VAR_SPACE);
  $yaxis_label = ImportHTTPVar("yaxis_label", VAR_ALPHA | VAR_SPACE);
  $yaxis_scale = ImportHTTPVar("yaxis_scale", VAR_DIGIT);
  $xaxis_grid = ImportHTTPVar("xaxis_grid", VAR_DIGIT);
  $yaxis_grid = ImportHTTPVar("yaxis_grid", VAR_DIGIT);
  $rotate_xaxis_lbl = ImportHTTPVar("rotate_xaxis_lbl", VAR_DIGIT);
  $style = ImportHTTPVar("style", VAR_ALPHA);
  $chart_type = ImportHTTPVar("chart_type", VAR_DIGIT);
  
  // Create the graph area, legends on bottom -- Alejandro
  $Graph =& new Image_Graph(array('driver'=>'gd', 'width'=>$width,'height'=>$height));
  $Graph->add(
    Image_Graph::vertical(
        Image_Graph::factory('title', array($title, 16)),
        Image_Graph::vertical(
            $Plotarea = Image_Graph::factory('plotarea'),
            $Legend = Image_Graph::factory('legend'),
            85
        ),
        10            
      )
    );

    if($style == "pie") {
        $Legend->setPlotarea($Plotarea);
    }
  $AxisX =& $Plotarea->getAxis(IMAGE_GRAPH_AXIS_X);

   // Create the dataset -- Alejandro
  $Dataset =& Image_Graph::factory('dataset'); 
  for ($i = 0; $i < count($xdata); $i++) {
      $Dataset->addPoint($xdata[$i][0], $xdata[$i][1]);
        /**
         * I'm limiting the number of elements by 15. Can't get nice graphs with
         * more than this. -- Alejandro
         */
        if($chart_type > 4) {
            if($i == 14) {
                break;
            }
        }
  }
  $Plot =& $Plotarea->addNew($style, $Dataset);  
  if ( $style == "pie" ) {
      $Plotarea->hideAxis();
      $Plot->explode(10);
  } else {
      $ArrayData =& Image_Graph::factory('Image_Graph_DataPreprocessor_Array',$Dataset);
      $AxisX->setDataPreprocessor($ArrayData);    
      $AxisX->setFontAngle('vertical');        
  }

$Marker =& $Plot->addNew('Image_Graph_Marker_Value', IMAGE_GRAPH_PCT_Y_TOTAL);
$PointingMarker =& $Plot->addNew('Image_Graph_Marker_Pointing_Angular', array(20, &$Marker));
$Plot->setMarker($PointingMarker);    
$Marker->setDataPreprocessor(Image_Graph::factory('Image_Graph_DataPreprocessor_Formatted', '%0.1f%%'));
$fill =& Image_Graph::factory('Image_Graph_Fill_Array');
if($style == "pie") {
    for($ff = 0; $ff < $i; $ff++) {
        // Need to be revisited. Thinking on getting a random color from the array. -- Alejandro
        $fill->addColor($named_colors[$ff]);
    }
} else {
     // Need to be revisited. If bar or line graphs, there's only one color.   -- Alejandro
    $fill->addColor("cyan");
}

// Default 'cosmetic' -- Alejandro
$Graph->setBackgroundColor('gray@0.2');
$Graph->setBorderColor('black');
$Graph->setPadding(10); 
$Plotarea->setBackgroundColor('white');
$Plotarea->setBorderColor('black');
$Plotarea->setPadding(10);
$Plot->setFillStyle($fill);
$Plot->Radius = 2;

// Show time! -- Alejandro
$Graph->done();

?>
