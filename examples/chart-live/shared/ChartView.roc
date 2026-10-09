import pf.RowVersion
import pf.CollectionPage

ChartView :: [].{
	Sample : { time : I64, value : I64, missing : Bool, key : Str }
	EditableSample : { sample_time : I64, expected_version : RowVersion, value : I64, missing : Bool }

	Chart : {
		width : I64,
		height : I64,
		start : I64,
		end : I64,
		title : Str,
		kind : Str,
		samples : CollectionPage(Sample),
		y_min : I64,
		y_max : I64,
	}

	Result : {
		title : Str,
		full_start : I64,
		full_end : I64,
		chart : Chart,
		sample_edits : CollectionPage(EditableSample),
	}

	fields = {
		title: "The page title for the selected UTC range.",
		full_start: "Inclusive lower bound of the app's initial UTC range.",
		full_end: "Exclusive upper bound of the app's initial UTC range.",
		sample_edits: {
			description: "Complete bounded page of owned rows in range for edit forms.",
			fields: {
				items: {
					description: "Current checked mutation fields.",
					each: {
						sample_time: "The immutable sample timestamp.",
						expected_version: "Current row version required by update_sample.",
						value: "Current stored value.",
						missing: "Current explicit missing marker.",
					},
				},
				has_more: "False: the actor's bounded collection fits this page.",
				next_after: "The start cursor; no continuation is required.",
			},
		},
		chart: {
			description: "Closed renderer input assembled from this actor's persisted samples.",
			fields: {
				width: "Fixed scene width of 640 pixels.",
				height: "Fixed scene height of 240 pixels.",
				start: "Inclusive UTC-millisecond range start.",
				end: "Exclusive UTC-millisecond range end.",
				title: "Chart title.",
				kind: "The fixed renderer kind, line.",
				samples: {
					description: "Complete bounded page of persisted samples in timestamp order.",
					fields: {
						items: {
							description: "Only these checked items are projected to the renderer.",
							each: {
								time: "UTC milliseconds since the Unix epoch.",
								value: "The stored integer value, including a genuine zero.",
								missing: "Explicit gap marker, independent of value.",
								key: "Stable nominal persistent sample reference encoded as text.",
							},
						},
						has_more: "False: the actor's bounded collection fits this page.",
						next_after: "The start cursor; no continuation is required.",
					},
				},
				y_min: "Fixed lower y-domain bound of zero.",
				y_max: "Fixed upper y-domain bound of 100.",
			},
		},
	}
}
