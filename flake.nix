{
  description = "Onesecret: read-once secret sharing for Logos Basecamp over Logos Messaging";

  inputs = {
    logos-module-builder.url = "github:logos-co/logos-module-builder";
    delivery_module.url = "github:logos-co/logos-delivery-module";
    # Optional: readers open links as a Logos name (LNS). Not bundled; used
    # when the user has the names module installed.
    names.url = "github:jefdiesel/logos-names?dir=basecamp-module";
    names.inputs.logos-module-builder.follows = "logos-module-builder";
  };

  outputs = inputs@{ logos-module-builder, ... }:
    logos-module-builder.lib.mkLogosQmlModule {
      src = ./.;
      configFile = ./metadata.json;
      flakeInputs = inputs;
    };
}
