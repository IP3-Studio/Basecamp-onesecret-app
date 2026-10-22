{
  description = "Onesecret: read-once secret sharing for Logos Basecamp over Logos Messaging";

  inputs = {
    logos-module-builder.url = "github:logos-co/logos-module-builder";
    delivery_module.url = "github:logos-co/logos-delivery-module";
  };

  outputs = inputs@{ logos-module-builder, ... }:
    logos-module-builder.lib.mkLogosQmlModule {
      src = ./.;
      configFile = ./metadata.json;
      flakeInputs = inputs;
    };
}
