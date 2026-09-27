module Reader
  def self.read(location)
    content = open(location) { |io| io.read(1000) }
    content.to_s
  end
end
