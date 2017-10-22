<?php
//
// QUICK Data Processing Script for Economics of Cyber Security
// NVD Database Datasets
// 20-10-2017
// Paul van der Knaap
//

echo '<pre>';
ob_start();
$files = glob("D:\\ECS\\*.json");
$vendorData = [];
foreach ($files as $file) {
	echo 'Loading file: ' . $file . "\n";
	$data = file_get_contents($file);
	$data = json_decode($data);

	$items = $data->CVE_Items;

	echo 'All items: ' . count($items) . "\n";

	$i = 0;

	foreach ($items as $item) {
		if (!isset($item->cve->affects->vendor->vendor_data)) {
			continue;
		}

		$vendors = &$item->cve->affects->vendor->vendor_data;

		foreach ($vendors as $vendor) {
			if ($vendor->vendor_name != 'microsoft' && $vendor->vendor_name != 'canonical' && $vendor->vendor_name != 'apple') {
				continue;
			}
			foreach ($vendor->product->product_data as $product) {
				if (!isset($vendorData[$vendor->vendor_name][$product->product_name])) {
					$vendorData[$vendor->vendor_name][$product->product_name]['_all'] = [];
					$vendorData[$vendor->vendor_name][$product->product_name]['_all']['total'] = 0;
					$vendorData[$vendor->vendor_name][$product->product_name]['_all']['dates'] = [];
				}
				
				$k = &$vendorData[$vendor->vendor_name][$product->product_name];

				foreach ($product->version->version_data as $v) {
					if (!isset($k[$v->version_value])) {
						$k[$v->version_value]['total'] = 0;
					}
					@$k[$v->version_value]['total']++;

					@$k['_all']['total']++;

					@$k['_all']['dates'][] = substr($item->publishedDate,0,10);
				}
			}

		}
	}

	echo "\n";
}
foreach ($vendorData as $k => $discard) {
	arsort($vendorData[$k]);
}


foreach($vendorData as $vendor=>$data){
	
	foreach($data as $product => $data2){
		if(!preg_match('/windows/',$product) && !preg_match('/ubuntu/',$product) && !preg_match('/mac/',$product)){
			continue;
		}
		
		$csv = 'vendor,product,datum'."\r\n";
		foreach($data2 as $versie=>$data3){
			if($versie != '_all'){
				continue;
			}
			
			foreach($data3['dates'] as $k=>$val){
				$csv .= $vendor.','.$product.','.$val."\r\n";
			}
		}
		file_put_contents('D:\\ECS\\csv-export\\data-export-'.$product.'.csv', $csv);
	}
}

print_r($vendorData);
$dataTxt = ob_get_clean();
echo $dataTxt;