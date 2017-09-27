<?php
//
// QUICK Data Processing Script for Economics of Cyber Security
// NVD Database Datasets
// 25-9-2017
//

echo '<pre>';
ob_start();
$files = glob("D:\\ECS\\*.json");
foreach ($files as $file) {
	echo 'Loading file: ' . $file . "\n";
	$data = file_get_contents($file);
	$data = json_decode($data);

	$items = $data->CVE_Items;

	echo 'All items: ' . count($items) . "\n";

	$i = 0;
	$vendorData = [];
	foreach ($items as $item) {
		if (!isset($item->cve->affects->vendor->vendor_data)) {
			continue;
		}

		$vendors = &$item->cve->affects->vendor->vendor_data;

		foreach ($vendors as $vendor) {
			if ($vendor->vendor_name != 'microsoft') {
				continue;
			}
			foreach ($vendor->product->product_data as $product) {
				if (!isset($vendorData[$vendor->vendor_name][$product->product_name])) {
					$vendorData[$vendor->vendor_name][$product->product_name]['_all'] = [];
					$vendorData[$vendor->vendor_name][$product->product_name]['_all']['total'] = 0;
					$vendorData[$vendor->vendor_name][$product->product_name]['_all']['UIR']  = [];
					$vendorData[$vendor->vendor_name][$product->product_name]['_all']['AV']  = [];

				}
				$k = &$vendorData[$vendor->vendor_name][$product->product_name];

				foreach ($product->version->version_data as $v) {
					if (!isset($k[$v->version_value])) {
						$k[$v->version_value]['total'] = 0;
						$k[$v->version_value]['UIR'] = [];
						$k[$v->version_value]['AV'] = [];
					}
					@$k[$v->version_value]['total']++;
					@$k[$v->version_value]['UIR'][$item->impact->baseMetricV3->cvssV3->userInteraction]++;
					@$k[$v->version_value]['AV'][$item->impact->baseMetricV3->cvssV3->attackVector]++;

					@$k['_all']['total']++;
					@$k['_all']['UIR'][$item->impact->baseMetricV3->cvssV3->userInteraction]++;
					@$k['_all']['AV'][$item->impact->baseMetricV3->cvssV3->attackVector]++;
				}
			}

		}
	}

	echo "\n";
}
foreach ($vendorData as $k => $discard) {
	arsort($vendorData[$k]);
}

$csv = 'vendor,product,versie,totaal,uir/none,uir/required,av/local,av/network,av/adjnetwork,av/physical'."\r\n";
foreach($vendorData as $vendor=>$data){
	foreach($data as $product => $data2){
		foreach($data2 as $versie=>$data3){
			$v1 = isset($data3['UIR']['NONE'])?$data3['UIR']['NONE']:0;
			$v2 = isset($data3['UIR']['REQUIRED'])?$data3['UIR']['REQUIRED']:0;

			$v3 = isset($data3['AV']['LOCAL'])?$data3['AV']['LOCAL']:0;
			$v4 = isset($data3['AV']['NETWORK'])?$data3['AV']['NETWORK']:0;
			$v5 = isset($data3['AV']['ADJACENT_NETWORK'])?$data3['AV']['ADJACENT_NETWORK']:0;
			$v6 = isset($data3['AV']['PHYSICAL'])?$data3['AV']['PHYSICAL']:0;
			$csv .= $vendor.','.$product.','.$versie.','.$data3['total'].','.$v1.','.$v2.','.$v3.','.$v4.','.$v5.','.$v6."\r\n";
		}
	}
}

file_put_contents('D:\\ECS\data-export-csv.csv', $csv);

print_r($vendorData);
$dataTxt = ob_get_clean();
echo $dataTxt;
file_put_contents('D:\\ECS\\data-export-outputPHP.txt', $dataTxt);
file_put_contents('D:\\ECS\\data-export.json', json_encode($vendorData));