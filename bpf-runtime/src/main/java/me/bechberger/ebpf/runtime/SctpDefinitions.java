/** Auto-generated */
package me.bechberger.ebpf.runtime;

import me.bechberger.ebpf.annotations.EnumMember;
import me.bechberger.ebpf.annotations.InlineUnion;
import me.bechberger.ebpf.annotations.Offset;
import me.bechberger.ebpf.annotations.OriginalName;
import me.bechberger.ebpf.annotations.Size;
import me.bechberger.ebpf.annotations.TrustedPtr;
import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction;
import me.bechberger.ebpf.annotations.bpf.NotUsableInJava;
import me.bechberger.ebpf.type.Enum;
import me.bechberger.ebpf.type.Ptr;
import me.bechberger.ebpf.type.Struct;
import me.bechberger.ebpf.type.TypedEnum;
import me.bechberger.ebpf.type.TypedefBase;
import me.bechberger.ebpf.type.Union;
import org.jetbrains.annotations.Nullable;
import static me.bechberger.ebpf.runtime.AaDefinitions.*;
import static me.bechberger.ebpf.runtime.AafsDefinitions.*;
import static me.bechberger.ebpf.runtime.Aat2870Definitions.*;
import static me.bechberger.ebpf.runtime.AccountDefinitions.*;
import static me.bechberger.ebpf.runtime.AcctDefinitions.*;
import static me.bechberger.ebpf.runtime.AcompDefinitions.*;
import static me.bechberger.ebpf.runtime.AcpiDefinitions.*;
import static me.bechberger.ebpf.runtime.AcpiphpDefinitions.*;
import static me.bechberger.ebpf.runtime.ActionDefinitions.*;
import static me.bechberger.ebpf.runtime.ActiveDefinitions.*;
import static me.bechberger.ebpf.runtime.AddDefinitions.*;
import static me.bechberger.ebpf.runtime.AddrDefinitions.*;
import static me.bechberger.ebpf.runtime.AddrconfDefinitions.*;
import static me.bechberger.ebpf.runtime.AdjustDefinitions.*;
import static me.bechberger.ebpf.runtime.AdlDefinitions.*;
import static me.bechberger.ebpf.runtime.Adp5520Definitions.*;
import static me.bechberger.ebpf.runtime.AdvisorDefinitions.*;
import static me.bechberger.ebpf.runtime.AeadDefinitions.*;
import static me.bechberger.ebpf.runtime.AerDefinitions.*;
import static me.bechberger.ebpf.runtime.AgpDefinitions.*;
import static me.bechberger.ebpf.runtime.AhashDefinitions.*;
import static me.bechberger.ebpf.runtime.AioDefinitions.*;
import static me.bechberger.ebpf.runtime.AlarmDefinitions.*;
import static me.bechberger.ebpf.runtime.AllocDefinitions.*;
import static me.bechberger.ebpf.runtime.AllocateDefinitions.*;
import static me.bechberger.ebpf.runtime.AmdDefinitions.*;
import static me.bechberger.ebpf.runtime.AmlDefinitions.*;
import static me.bechberger.ebpf.runtime.AnonDefinitions.*;
import static me.bechberger.ebpf.runtime.ApeiDefinitions.*;
import static me.bechberger.ebpf.runtime.ApicDefinitions.*;
import static me.bechberger.ebpf.runtime.ApparmorDefinitions.*;
import static me.bechberger.ebpf.runtime.AppendDefinitions.*;
import static me.bechberger.ebpf.runtime.ApplyDefinitions.*;
import static me.bechberger.ebpf.runtime.ArchDefinitions.*;
import static me.bechberger.ebpf.runtime.ArenaDefinitions.*;
import static me.bechberger.ebpf.runtime.ArpDefinitions.*;
import static me.bechberger.ebpf.runtime.ArrayDefinitions.*;
import static me.bechberger.ebpf.runtime.Asn1Definitions.*;
import static me.bechberger.ebpf.runtime.AssocDefinitions.*;
import static me.bechberger.ebpf.runtime.AsymmetricDefinitions.*;
import static me.bechberger.ebpf.runtime.AsyncDefinitions.*;
import static me.bechberger.ebpf.runtime.AtaDefinitions.*;
import static me.bechberger.ebpf.runtime.AtkbdDefinitions.*;
import static me.bechberger.ebpf.runtime.AtomicDefinitions.*;
import static me.bechberger.ebpf.runtime.AttachDefinitions.*;
import static me.bechberger.ebpf.runtime.AttributeDefinitions.*;
import static me.bechberger.ebpf.runtime.AuditDefinitions.*;
import static me.bechberger.ebpf.runtime.AuxiliaryDefinitions.*;
import static me.bechberger.ebpf.runtime.AvailableDefinitions.*;
import static me.bechberger.ebpf.runtime.AvcDefinitions.*;
import static me.bechberger.ebpf.runtime.AvtabDefinitions.*;
import static me.bechberger.ebpf.runtime.BackingDefinitions.*;
import static me.bechberger.ebpf.runtime.BacklightDefinitions.*;
import static me.bechberger.ebpf.runtime.BadDefinitions.*;
import static me.bechberger.ebpf.runtime.BadblocksDefinitions.*;
import static me.bechberger.ebpf.runtime.BalanceDefinitions.*;
import static me.bechberger.ebpf.runtime.BalloonDefinitions.*;
import static me.bechberger.ebpf.runtime.BdevDefinitions.*;
import static me.bechberger.ebpf.runtime.BdiDefinitions.*;
import static me.bechberger.ebpf.runtime.BgpioDefinitions.*;
import static me.bechberger.ebpf.runtime.BhDefinitions.*;
import static me.bechberger.ebpf.runtime.BindDefinitions.*;
import static me.bechberger.ebpf.runtime.BioDefinitions.*;
import static me.bechberger.ebpf.runtime.BitmapDefinitions.*;
import static me.bechberger.ebpf.runtime.Blake2sDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkcgDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkdevDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkgDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkifDefinitions.*;
import static me.bechberger.ebpf.runtime.BlockDefinitions.*;
import static me.bechberger.ebpf.runtime.BloomDefinitions.*;
import static me.bechberger.ebpf.runtime.BootDefinitions.*;
import static me.bechberger.ebpf.runtime.BpfDefinitions.*;
import static me.bechberger.ebpf.runtime.BqlDefinitions.*;
import static me.bechberger.ebpf.runtime.BsgDefinitions.*;
import static me.bechberger.ebpf.runtime.BtfDefinitions.*;
import static me.bechberger.ebpf.runtime.BtreeDefinitions.*;
import static me.bechberger.ebpf.runtime.BtsDefinitions.*;
import static me.bechberger.ebpf.runtime.BufferDefinitions.*;
import static me.bechberger.ebpf.runtime.BuildDefinitions.*;
import static me.bechberger.ebpf.runtime.BusDefinitions.*;
import static me.bechberger.ebpf.runtime.BytDefinitions.*;
import static me.bechberger.ebpf.runtime.CacheDefinitions.*;
import static me.bechberger.ebpf.runtime.CalcDefinitions.*;
import static me.bechberger.ebpf.runtime.CalculateDefinitions.*;
import static me.bechberger.ebpf.runtime.CalipsoDefinitions.*;
import static me.bechberger.ebpf.runtime.CallDefinitions.*;
import static me.bechberger.ebpf.runtime.CanDefinitions.*;
import static me.bechberger.ebpf.runtime.CapDefinitions.*;
import static me.bechberger.ebpf.runtime.CcDefinitions.*;
import static me.bechberger.ebpf.runtime.CdevDefinitions.*;
import static me.bechberger.ebpf.runtime.CdromDefinitions.*;
import static me.bechberger.ebpf.runtime.CeaDefinitions.*;
import static me.bechberger.ebpf.runtime.Cfg80211Definitions.*;
import static me.bechberger.ebpf.runtime.Cgroup1Definitions.*;
import static me.bechberger.ebpf.runtime.CgroupDefinitions.*;
import static me.bechberger.ebpf.runtime.ChangeDefinitions.*;
import static me.bechberger.ebpf.runtime.ChargerDefinitions.*;
import static me.bechberger.ebpf.runtime.CheckDefinitions.*;
import static me.bechberger.ebpf.runtime.ChvDefinitions.*;
import static me.bechberger.ebpf.runtime.CipsoDefinitions.*;
import static me.bechberger.ebpf.runtime.ClassDefinitions.*;
import static me.bechberger.ebpf.runtime.CleanDefinitions.*;
import static me.bechberger.ebpf.runtime.CleanupDefinitions.*;
import static me.bechberger.ebpf.runtime.ClearDefinitions.*;
import static me.bechberger.ebpf.runtime.ClkDefinitions.*;
import static me.bechberger.ebpf.runtime.ClockeventsDefinitions.*;
import static me.bechberger.ebpf.runtime.ClocksourceDefinitions.*;
import static me.bechberger.ebpf.runtime.ClosureDefinitions.*;
import static me.bechberger.ebpf.runtime.CmaDefinitions.*;
import static me.bechberger.ebpf.runtime.CmciDefinitions.*;
import static me.bechberger.ebpf.runtime.CmdlineDefinitions.*;
import static me.bechberger.ebpf.runtime.CmisDefinitions.*;
import static me.bechberger.ebpf.runtime.CmosDefinitions.*;
import static me.bechberger.ebpf.runtime.CmpDefinitions.*;
import static me.bechberger.ebpf.runtime.CnDefinitions.*;
import static me.bechberger.ebpf.runtime.CollapseDefinitions.*;
import static me.bechberger.ebpf.runtime.CollectDefinitions.*;
import static me.bechberger.ebpf.runtime.CommonDefinitions.*;
import static me.bechberger.ebpf.runtime.CompactionDefinitions.*;
import static me.bechberger.ebpf.runtime.CompatDefinitions.*;
import static me.bechberger.ebpf.runtime.ComponentDefinitions.*;
import static me.bechberger.ebpf.runtime.ComputeDefinitions.*;
import static me.bechberger.ebpf.runtime.ConDefinitions.*;
import static me.bechberger.ebpf.runtime.CondDefinitions.*;
import static me.bechberger.ebpf.runtime.ConfigDefinitions.*;
import static me.bechberger.ebpf.runtime.ConfigfsDefinitions.*;
import static me.bechberger.ebpf.runtime.ConsoleDefinitions.*;
import static me.bechberger.ebpf.runtime.ContextDefinitions.*;
import static me.bechberger.ebpf.runtime.ConvertDefinitions.*;
import static me.bechberger.ebpf.runtime.CookieDefinitions.*;
import static me.bechberger.ebpf.runtime.CopyDefinitions.*;
import static me.bechberger.ebpf.runtime.CoreDefinitions.*;
import static me.bechberger.ebpf.runtime.CoredumpDefinitions.*;
import static me.bechberger.ebpf.runtime.CountDefinitions.*;
import static me.bechberger.ebpf.runtime.CpciDefinitions.*;
import static me.bechberger.ebpf.runtime.CperDefinitions.*;
import static me.bechberger.ebpf.runtime.CppcDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuacctDefinitions.*;
import static me.bechberger.ebpf.runtime.CpufreqDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuhpDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuidleDefinitions.*;
import static me.bechberger.ebpf.runtime.CpumaskDefinitions.*;
import static me.bechberger.ebpf.runtime.CpusDefinitions.*;
import static me.bechberger.ebpf.runtime.CpusetDefinitions.*;
import static me.bechberger.ebpf.runtime.CrashDefinitions.*;
import static me.bechberger.ebpf.runtime.CrbDefinitions.*;
import static me.bechberger.ebpf.runtime.Crc64Definitions.*;
import static me.bechberger.ebpf.runtime.CreateDefinitions.*;
import static me.bechberger.ebpf.runtime.CryptoDefinitions.*;
import static me.bechberger.ebpf.runtime.CrystalcoveDefinitions.*;
import static me.bechberger.ebpf.runtime.CssDefinitions.*;
import static me.bechberger.ebpf.runtime.CsumDefinitions.*;
import static me.bechberger.ebpf.runtime.CtDefinitions.*;
import static me.bechberger.ebpf.runtime.CtrlDefinitions.*;
import static me.bechberger.ebpf.runtime.CtxDefinitions.*;
import static me.bechberger.ebpf.runtime.CurrentDefinitions.*;
import static me.bechberger.ebpf.runtime.CxlDefinitions.*;
import static me.bechberger.ebpf.runtime.DDefinitions.*;
import static me.bechberger.ebpf.runtime.Da903xDefinitions.*;
import static me.bechberger.ebpf.runtime.Da9052Definitions.*;
import static me.bechberger.ebpf.runtime.Da9063Definitions.*;
import static me.bechberger.ebpf.runtime.DataDefinitions.*;
import static me.bechberger.ebpf.runtime.DaxDefinitions.*;
import static me.bechberger.ebpf.runtime.DbcDefinitions.*;
import static me.bechberger.ebpf.runtime.DbgDefinitions.*;
import static me.bechberger.ebpf.runtime.DcbDefinitions.*;
import static me.bechberger.ebpf.runtime.DcbnlDefinitions.*;
import static me.bechberger.ebpf.runtime.DdDefinitions.*;
import static me.bechberger.ebpf.runtime.DdebugDefinitions.*;
import static me.bechberger.ebpf.runtime.DeadlineDefinitions.*;
import static me.bechberger.ebpf.runtime.DebugDefinitions.*;
import static me.bechberger.ebpf.runtime.DebugfsDefinitions.*;
import static me.bechberger.ebpf.runtime.DecDefinitions.*;
import static me.bechberger.ebpf.runtime.DefaultDefinitions.*;
import static me.bechberger.ebpf.runtime.DeferredDefinitions.*;
import static me.bechberger.ebpf.runtime.DeflateDefinitions.*;
import static me.bechberger.ebpf.runtime.DelayacctDefinitions.*;
import static me.bechberger.ebpf.runtime.DelayedDefinitions.*;
import static me.bechberger.ebpf.runtime.DeleteDefinitions.*;
import static me.bechberger.ebpf.runtime.DentryDefinitions.*;
import static me.bechberger.ebpf.runtime.DequeueDefinitions.*;
import static me.bechberger.ebpf.runtime.DescDefinitions.*;
import static me.bechberger.ebpf.runtime.DestroyDefinitions.*;
import static me.bechberger.ebpf.runtime.DetachDefinitions.*;
import static me.bechberger.ebpf.runtime.DevDefinitions.*;
import static me.bechberger.ebpf.runtime.DevcdDefinitions.*;
import static me.bechberger.ebpf.runtime.DevfreqDefinitions.*;
import static me.bechberger.ebpf.runtime.DeviceDefinitions.*;
import static me.bechberger.ebpf.runtime.DevlDefinitions.*;
import static me.bechberger.ebpf.runtime.DevlinkDefinitions.*;
import static me.bechberger.ebpf.runtime.DevmDefinitions.*;
import static me.bechberger.ebpf.runtime.DevptsDefinitions.*;
import static me.bechberger.ebpf.runtime.DevresDefinitions.*;
import static me.bechberger.ebpf.runtime.DhDefinitions.*;
import static me.bechberger.ebpf.runtime.DimDefinitions.*;
import static me.bechberger.ebpf.runtime.DisableDefinitions.*;
import static me.bechberger.ebpf.runtime.DiskDefinitions.*;
import static me.bechberger.ebpf.runtime.DispatchDefinitions.*;
import static me.bechberger.ebpf.runtime.DisplayidDefinitions.*;
import static me.bechberger.ebpf.runtime.DlDefinitions.*;
import static me.bechberger.ebpf.runtime.DmDefinitions.*;
import static me.bechberger.ebpf.runtime.DmaDefinitions.*;
import static me.bechberger.ebpf.runtime.DmabufDefinitions.*;
import static me.bechberger.ebpf.runtime.DmaengineDefinitions.*;
import static me.bechberger.ebpf.runtime.DmarDefinitions.*;
import static me.bechberger.ebpf.runtime.DmemDefinitions.*;
import static me.bechberger.ebpf.runtime.DmiDefinitions.*;
import static me.bechberger.ebpf.runtime.DnsDefinitions.*;
import static me.bechberger.ebpf.runtime.DoDefinitions.*;
import static me.bechberger.ebpf.runtime.DomainDefinitions.*;
import static me.bechberger.ebpf.runtime.DownDefinitions.*;
import static me.bechberger.ebpf.runtime.DpcDefinitions.*;
import static me.bechberger.ebpf.runtime.DpllDefinitions.*;
import static me.bechberger.ebpf.runtime.DpmDefinitions.*;
import static me.bechberger.ebpf.runtime.DquotDefinitions.*;
import static me.bechberger.ebpf.runtime.DrainDefinitions.*;
import static me.bechberger.ebpf.runtime.DrbgDefinitions.*;
import static me.bechberger.ebpf.runtime.DriverDefinitions.*;
import static me.bechberger.ebpf.runtime.DrmDefinitions.*;
import static me.bechberger.ebpf.runtime.DrmmDefinitions.*;
import static me.bechberger.ebpf.runtime.DropDefinitions.*;
import static me.bechberger.ebpf.runtime.DsaDefinitions.*;
import static me.bechberger.ebpf.runtime.DstDefinitions.*;
import static me.bechberger.ebpf.runtime.DummyDefinitions.*;
import static me.bechberger.ebpf.runtime.DummyconDefinitions.*;
import static me.bechberger.ebpf.runtime.DumpDefinitions.*;
import static me.bechberger.ebpf.runtime.DupDefinitions.*;
import static me.bechberger.ebpf.runtime.DvdDefinitions.*;
import static me.bechberger.ebpf.runtime.DwDefinitions.*;
import static me.bechberger.ebpf.runtime.Dwc2Definitions.*;
import static me.bechberger.ebpf.runtime.DxDefinitions.*;
import static me.bechberger.ebpf.runtime.DynDefinitions.*;
import static me.bechberger.ebpf.runtime.DyneventDefinitions.*;
import static me.bechberger.ebpf.runtime.EafnosupportDefinitions.*;
import static me.bechberger.ebpf.runtime.EarlyDefinitions.*;
import static me.bechberger.ebpf.runtime.EbitmapDefinitions.*;
import static me.bechberger.ebpf.runtime.EcDefinitions.*;
import static me.bechberger.ebpf.runtime.EccDefinitions.*;
import static me.bechberger.ebpf.runtime.EcryptfsDefinitions.*;
import static me.bechberger.ebpf.runtime.EdacDefinitions.*;
import static me.bechberger.ebpf.runtime.EddDefinitions.*;
import static me.bechberger.ebpf.runtime.EdidDefinitions.*;
import static me.bechberger.ebpf.runtime.EfiDefinitions.*;
import static me.bechberger.ebpf.runtime.EfivarDefinitions.*;
import static me.bechberger.ebpf.runtime.EfivarfsDefinitions.*;
import static me.bechberger.ebpf.runtime.EhciDefinitions.*;
import static me.bechberger.ebpf.runtime.ElantsDefinitions.*;
import static me.bechberger.ebpf.runtime.ElevatorDefinitions.*;
import static me.bechberger.ebpf.runtime.ElfDefinitions.*;
import static me.bechberger.ebpf.runtime.ElvDefinitions.*;
import static me.bechberger.ebpf.runtime.EmDefinitions.*;
import static me.bechberger.ebpf.runtime.EmitDefinitions.*;
import static me.bechberger.ebpf.runtime.EnableDefinitions.*;
import static me.bechberger.ebpf.runtime.EndDefinitions.*;
import static me.bechberger.ebpf.runtime.EnqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.EpDefinitions.*;
import static me.bechberger.ebpf.runtime.EprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.ErstDefinitions.*;
import static me.bechberger.ebpf.runtime.EspintcpDefinitions.*;
import static me.bechberger.ebpf.runtime.EthDefinitions.*;
import static me.bechberger.ebpf.runtime.EthnlDefinitions.*;
import static me.bechberger.ebpf.runtime.EthtoolDefinitions.*;
import static me.bechberger.ebpf.runtime.EvdevDefinitions.*;
import static me.bechberger.ebpf.runtime.EventDefinitions.*;
import static me.bechberger.ebpf.runtime.EventfdDefinitions.*;
import static me.bechberger.ebpf.runtime.EventfsDefinitions.*;
import static me.bechberger.ebpf.runtime.EvmDefinitions.*;
import static me.bechberger.ebpf.runtime.EvtchnDefinitions.*;
import static me.bechberger.ebpf.runtime.ExcDefinitions.*;
import static me.bechberger.ebpf.runtime.ExecmemDefinitions.*;
import static me.bechberger.ebpf.runtime.ExitDefinitions.*;
import static me.bechberger.ebpf.runtime.Ext4Definitions.*;
import static me.bechberger.ebpf.runtime.ExtconDefinitions.*;
import static me.bechberger.ebpf.runtime.FDefinitions.*;
import static me.bechberger.ebpf.runtime.FanotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.FatDefinitions.*;
import static me.bechberger.ebpf.runtime.FaultDefinitions.*;
import static me.bechberger.ebpf.runtime.FauxDefinitions.*;
import static me.bechberger.ebpf.runtime.FbDefinitions.*;
import static me.bechberger.ebpf.runtime.FbconDefinitions.*;
import static me.bechberger.ebpf.runtime.FdtDefinitions.*;
import static me.bechberger.ebpf.runtime.FfDefinitions.*;
import static me.bechberger.ebpf.runtime.FgraphDefinitions.*;
import static me.bechberger.ebpf.runtime.Fib4Definitions.*;
import static me.bechberger.ebpf.runtime.Fib6Definitions.*;
import static me.bechberger.ebpf.runtime.FibDefinitions.*;
import static me.bechberger.ebpf.runtime.FifoDefinitions.*;
import static me.bechberger.ebpf.runtime.FileDefinitions.*;
import static me.bechberger.ebpf.runtime.FilemapDefinitions.*;
import static me.bechberger.ebpf.runtime.FilenameDefinitions.*;
import static me.bechberger.ebpf.runtime.FillDefinitions.*;
import static me.bechberger.ebpf.runtime.FilterDefinitions.*;
import static me.bechberger.ebpf.runtime.FindDefinitions.*;
import static me.bechberger.ebpf.runtime.FinishDefinitions.*;
import static me.bechberger.ebpf.runtime.FirmwareDefinitions.*;
import static me.bechberger.ebpf.runtime.FixedDefinitions.*;
import static me.bechberger.ebpf.runtime.FixupDefinitions.*;
import static me.bechberger.ebpf.runtime.FlowDefinitions.*;
import static me.bechberger.ebpf.runtime.FlushDefinitions.*;
import static me.bechberger.ebpf.runtime.FnDefinitions.*;
import static me.bechberger.ebpf.runtime.FolioDefinitions.*;
import static me.bechberger.ebpf.runtime.FollowDefinitions.*;
import static me.bechberger.ebpf.runtime.FopsDefinitions.*;
import static me.bechberger.ebpf.runtime.ForDefinitions.*;
import static me.bechberger.ebpf.runtime.ForceDefinitions.*;
import static me.bechberger.ebpf.runtime.FprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.FpuDefinitions.*;
import static me.bechberger.ebpf.runtime.FredDefinitions.*;
import static me.bechberger.ebpf.runtime.FreeDefinitions.*;
import static me.bechberger.ebpf.runtime.FreezeDefinitions.*;
import static me.bechberger.ebpf.runtime.FreezerDefinitions.*;
import static me.bechberger.ebpf.runtime.FreqDefinitions.*;
import static me.bechberger.ebpf.runtime.FromDefinitions.*;
import static me.bechberger.ebpf.runtime.FsDefinitions.*;
import static me.bechberger.ebpf.runtime.FscryptDefinitions.*;
import static me.bechberger.ebpf.runtime.FseDefinitions.*;
import static me.bechberger.ebpf.runtime.FsnotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.FsverityDefinitions.*;
import static me.bechberger.ebpf.runtime.FtraceDefinitions.*;
import static me.bechberger.ebpf.runtime.FullDefinitions.*;
import static me.bechberger.ebpf.runtime.FunctionDefinitions.*;
import static me.bechberger.ebpf.runtime.FuseDefinitions.*;
import static me.bechberger.ebpf.runtime.FutexDefinitions.*;
import static me.bechberger.ebpf.runtime.FwDefinitions.*;
import static me.bechberger.ebpf.runtime.FwnodeDefinitions.*;
import static me.bechberger.ebpf.runtime.GartDefinitions.*;
import static me.bechberger.ebpf.runtime.GcmDefinitions.*;
import static me.bechberger.ebpf.runtime.GenDefinitions.*;
import static me.bechberger.ebpf.runtime.GenericDefinitions.*;
import static me.bechberger.ebpf.runtime.GenlDefinitions.*;
import static me.bechberger.ebpf.runtime.GenpdDefinitions.*;
import static me.bechberger.ebpf.runtime.GenphyDefinitions.*;
import static me.bechberger.ebpf.runtime.GetDefinitions.*;
import static me.bechberger.ebpf.runtime.GhesDefinitions.*;
import static me.bechberger.ebpf.runtime.GnetDefinitions.*;
import static me.bechberger.ebpf.runtime.GnttabDefinitions.*;
import static me.bechberger.ebpf.runtime.GpioDefinitions.*;
import static me.bechberger.ebpf.runtime.GpiochipDefinitions.*;
import static me.bechberger.ebpf.runtime.GpiodDefinitions.*;
import static me.bechberger.ebpf.runtime.GpiolibDefinitions.*;
import static me.bechberger.ebpf.runtime.GroDefinitions.*;
import static me.bechberger.ebpf.runtime.GroupDefinitions.*;
import static me.bechberger.ebpf.runtime.GupDefinitions.*;
import static me.bechberger.ebpf.runtime.HandleDefinitions.*;
import static me.bechberger.ebpf.runtime.HandshakeDefinitions.*;
import static me.bechberger.ebpf.runtime.HasDefinitions.*;
import static me.bechberger.ebpf.runtime.HashDefinitions.*;
import static me.bechberger.ebpf.runtime.HcdDefinitions.*;
import static me.bechberger.ebpf.runtime.HctxDefinitions.*;
import static me.bechberger.ebpf.runtime.HdmiDefinitions.*;
import static me.bechberger.ebpf.runtime.HfiDefinitions.*;
import static me.bechberger.ebpf.runtime.HidDefinitions.*;
import static me.bechberger.ebpf.runtime.HistDefinitions.*;
import static me.bechberger.ebpf.runtime.HmacDefinitions.*;
import static me.bechberger.ebpf.runtime.HmatDefinitions.*;
import static me.bechberger.ebpf.runtime.HmmDefinitions.*;
import static me.bechberger.ebpf.runtime.HookDefinitions.*;
import static me.bechberger.ebpf.runtime.HpetDefinitions.*;
import static me.bechberger.ebpf.runtime.HrtimerDefinitions.*;
import static me.bechberger.ebpf.runtime.HsuDefinitions.*;
import static me.bechberger.ebpf.runtime.HswepDefinitions.*;
import static me.bechberger.ebpf.runtime.HtabDefinitions.*;
import static me.bechberger.ebpf.runtime.HteDefinitions.*;
import static me.bechberger.ebpf.runtime.HubDefinitions.*;
import static me.bechberger.ebpf.runtime.HufDefinitions.*;
import static me.bechberger.ebpf.runtime.HugepageDefinitions.*;
import static me.bechberger.ebpf.runtime.HugetlbDefinitions.*;
import static me.bechberger.ebpf.runtime.HugetlbfsDefinitions.*;
import static me.bechberger.ebpf.runtime.HvDefinitions.*;
import static me.bechberger.ebpf.runtime.HvcDefinitions.*;
import static me.bechberger.ebpf.runtime.HwDefinitions.*;
import static me.bechberger.ebpf.runtime.HwlatDefinitions.*;
import static me.bechberger.ebpf.runtime.HwmonDefinitions.*;
import static me.bechberger.ebpf.runtime.HybridDefinitions.*;
import static me.bechberger.ebpf.runtime.HypervDefinitions.*;
import static me.bechberger.ebpf.runtime.HypervisorDefinitions.*;
import static me.bechberger.ebpf.runtime.I2cDefinitions.*;
import static me.bechberger.ebpf.runtime.I2cdevDefinitions.*;
import static me.bechberger.ebpf.runtime.I8042Definitions.*;
import static me.bechberger.ebpf.runtime.Ia32Definitions.*;
import static me.bechberger.ebpf.runtime.IbDefinitions.*;
import static me.bechberger.ebpf.runtime.IccDefinitions.*;
import static me.bechberger.ebpf.runtime.IcmpDefinitions.*;
import static me.bechberger.ebpf.runtime.Icmpv6Definitions.*;
import static me.bechberger.ebpf.runtime.IcxDefinitions.*;
import static me.bechberger.ebpf.runtime.IdleDefinitions.*;
import static me.bechberger.ebpf.runtime.IdrDefinitions.*;
import static me.bechberger.ebpf.runtime.Ieee80211Definitions.*;
import static me.bechberger.ebpf.runtime.IflaDefinitions.*;
import static me.bechberger.ebpf.runtime.Igmp6Definitions.*;
import static me.bechberger.ebpf.runtime.IgmpDefinitions.*;
import static me.bechberger.ebpf.runtime.ImaDefinitions.*;
import static me.bechberger.ebpf.runtime.ImsttfbDefinitions.*;
import static me.bechberger.ebpf.runtime.In6Definitions.*;
import static me.bechberger.ebpf.runtime.InDefinitions.*;
import static me.bechberger.ebpf.runtime.IncDefinitions.*;
import static me.bechberger.ebpf.runtime.Inet6Definitions.*;
import static me.bechberger.ebpf.runtime.InetDefinitions.*;
import static me.bechberger.ebpf.runtime.InitDefinitions.*;
import static me.bechberger.ebpf.runtime.InodeDefinitions.*;
import static me.bechberger.ebpf.runtime.InotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.InputDefinitions.*;
import static me.bechberger.ebpf.runtime.InsertDefinitions.*;
import static me.bechberger.ebpf.runtime.InsnDefinitions.*;
import static me.bechberger.ebpf.runtime.IntDefinitions.*;
import static me.bechberger.ebpf.runtime.IntegrityDefinitions.*;
import static me.bechberger.ebpf.runtime.IntelDefinitions.*;
import static me.bechberger.ebpf.runtime.IntervalDefinitions.*;
import static me.bechberger.ebpf.runtime.InvalidateDefinitions.*;
import static me.bechberger.ebpf.runtime.IoDefinitions.*;
import static me.bechberger.ebpf.runtime.Ioam6Definitions.*;
import static me.bechberger.ebpf.runtime.IoapicDefinitions.*;
import static me.bechberger.ebpf.runtime.IocDefinitions.*;
import static me.bechberger.ebpf.runtime.IocgDefinitions.*;
import static me.bechberger.ebpf.runtime.IoctlDefinitions.*;
import static me.bechberger.ebpf.runtime.IomapDefinitions.*;
import static me.bechberger.ebpf.runtime.IommuDefinitions.*;
import static me.bechberger.ebpf.runtime.IommufdDefinitions.*;
import static me.bechberger.ebpf.runtime.IopfDefinitions.*;
import static me.bechberger.ebpf.runtime.IoremapDefinitions.*;
import static me.bechberger.ebpf.runtime.IosfDefinitions.*;
import static me.bechberger.ebpf.runtime.IovDefinitions.*;
import static me.bechberger.ebpf.runtime.IovaDefinitions.*;
import static me.bechberger.ebpf.runtime.Ip4Definitions.*;
import static me.bechberger.ebpf.runtime.Ip6Definitions.*;
import static me.bechberger.ebpf.runtime.Ip6addrlblDefinitions.*;
import static me.bechberger.ebpf.runtime.Ip6mrDefinitions.*;
import static me.bechberger.ebpf.runtime.IpDefinitions.*;
import static me.bechberger.ebpf.runtime.IpcDefinitions.*;
import static me.bechberger.ebpf.runtime.IpeDefinitions.*;
import static me.bechberger.ebpf.runtime.IpmrDefinitions.*;
import static me.bechberger.ebpf.runtime.Ipv4Definitions.*;
import static me.bechberger.ebpf.runtime.Ipv6Definitions.*;
import static me.bechberger.ebpf.runtime.IrqDefinitions.*;
import static me.bechberger.ebpf.runtime.IrteDefinitions.*;
import static me.bechberger.ebpf.runtime.IsDefinitions.*;
import static me.bechberger.ebpf.runtime.IsaDefinitions.*;
import static me.bechberger.ebpf.runtime.IsolateDefinitions.*;
import static me.bechberger.ebpf.runtime.IterDefinitions.*;
import static me.bechberger.ebpf.runtime.IvbepDefinitions.*;
import static me.bechberger.ebpf.runtime.IwDefinitions.*;
import static me.bechberger.ebpf.runtime.JailhouseDefinitions.*;
import static me.bechberger.ebpf.runtime.Jbd2Definitions.*;
import static me.bechberger.ebpf.runtime.JentDefinitions.*;
import static me.bechberger.ebpf.runtime.JournalDefinitions.*;
import static me.bechberger.ebpf.runtime.JumpDefinitions.*;
import static me.bechberger.ebpf.runtime.KDefinitions.*;
import static me.bechberger.ebpf.runtime.KallsymsDefinitions.*;
import static me.bechberger.ebpf.runtime.KbdDefinitions.*;
import static me.bechberger.ebpf.runtime.KdbDefinitions.*;
import static me.bechberger.ebpf.runtime.KernDefinitions.*;
import static me.bechberger.ebpf.runtime.KernelDefinitions.*;
import static me.bechberger.ebpf.runtime.KernfsDefinitions.*;
import static me.bechberger.ebpf.runtime.KexecDefinitions.*;
import static me.bechberger.ebpf.runtime.KeyDefinitions.*;
import static me.bechberger.ebpf.runtime.KeyctlDefinitions.*;
import static me.bechberger.ebpf.runtime.KeyringDefinitions.*;
import static me.bechberger.ebpf.runtime.KfenceDefinitions.*;
import static me.bechberger.ebpf.runtime.KfifoDefinitions.*;
import static me.bechberger.ebpf.runtime.KfreeDefinitions.*;
import static me.bechberger.ebpf.runtime.KgdbDefinitions.*;
import static me.bechberger.ebpf.runtime.KgdbocDefinitions.*;
import static me.bechberger.ebpf.runtime.KhoDefinitions.*;
import static me.bechberger.ebpf.runtime.KillDefinitions.*;
import static me.bechberger.ebpf.runtime.KimageDefinitions.*;
import static me.bechberger.ebpf.runtime.KlistDefinitions.*;
import static me.bechberger.ebpf.runtime.KlpDefinitions.*;
import static me.bechberger.ebpf.runtime.KmallocDefinitions.*;
import static me.bechberger.ebpf.runtime.KmemDefinitions.*;
import static me.bechberger.ebpf.runtime.KmsgDefinitions.*;
import static me.bechberger.ebpf.runtime.KobjDefinitions.*;
import static me.bechberger.ebpf.runtime.KobjectDefinitions.*;
import static me.bechberger.ebpf.runtime.KprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.KsmDefinitions.*;
import static me.bechberger.ebpf.runtime.KsysDefinitions.*;
import static me.bechberger.ebpf.runtime.KthreadDefinitions.*;
import static me.bechberger.ebpf.runtime.KtimeDefinitions.*;
import static me.bechberger.ebpf.runtime.KvmDefinitions.*;
import static me.bechberger.ebpf.runtime.L3mdevDefinitions.*;
import static me.bechberger.ebpf.runtime.LabelDefinitions.*;
import static me.bechberger.ebpf.runtime.LandlockDefinitions.*;
import static me.bechberger.ebpf.runtime.LapicDefinitions.*;
import static me.bechberger.ebpf.runtime.LdmDefinitions.*;
import static me.bechberger.ebpf.runtime.LdmaDefinitions.*;
import static me.bechberger.ebpf.runtime.LedDefinitions.*;
import static me.bechberger.ebpf.runtime.LedtrigDefinitions.*;
import static me.bechberger.ebpf.runtime.LegacyDefinitions.*;
import static me.bechberger.ebpf.runtime.LinearDefinitions.*;
import static me.bechberger.ebpf.runtime.LineeventDefinitions.*;
import static me.bechberger.ebpf.runtime.LinereqDefinitions.*;
import static me.bechberger.ebpf.runtime.LinkDefinitions.*;
import static me.bechberger.ebpf.runtime.LinuxDefinitions.*;
import static me.bechberger.ebpf.runtime.ListDefinitions.*;
import static me.bechberger.ebpf.runtime.LoadDefinitions.*;
import static me.bechberger.ebpf.runtime.LocalDefinitions.*;
import static me.bechberger.ebpf.runtime.LockDefinitions.*;
import static me.bechberger.ebpf.runtime.LocksDefinitions.*;
import static me.bechberger.ebpf.runtime.LockupDefinitions.*;
import static me.bechberger.ebpf.runtime.LogDefinitions.*;
import static me.bechberger.ebpf.runtime.LookupDefinitions.*;
import static me.bechberger.ebpf.runtime.LoopDefinitions.*;
import static me.bechberger.ebpf.runtime.Lp8788Definitions.*;
import static me.bechberger.ebpf.runtime.LpssDefinitions.*;
import static me.bechberger.ebpf.runtime.LruDefinitions.*;
import static me.bechberger.ebpf.runtime.LskcipherDefinitions.*;
import static me.bechberger.ebpf.runtime.LsmDefinitions.*;
import static me.bechberger.ebpf.runtime.LwtunnelDefinitions.*;
import static me.bechberger.ebpf.runtime.Lz4Definitions.*;
import static me.bechberger.ebpf.runtime.MachineDefinitions.*;
import static me.bechberger.ebpf.runtime.MacsecDefinitions.*;
import static me.bechberger.ebpf.runtime.MadviseDefinitions.*;
import static me.bechberger.ebpf.runtime.MakeDefinitions.*;
import static me.bechberger.ebpf.runtime.MapDefinitions.*;
import static me.bechberger.ebpf.runtime.MapleDefinitions.*;
import static me.bechberger.ebpf.runtime.MarkDefinitions.*;
import static me.bechberger.ebpf.runtime.MasDefinitions.*;
import static me.bechberger.ebpf.runtime.MatchDefinitions.*;
import static me.bechberger.ebpf.runtime.Max310xDefinitions.*;
import static me.bechberger.ebpf.runtime.Max77693Definitions.*;
import static me.bechberger.ebpf.runtime.Max8925Definitions.*;
import static me.bechberger.ebpf.runtime.Max8997Definitions.*;
import static me.bechberger.ebpf.runtime.Max8998Definitions.*;
import static me.bechberger.ebpf.runtime.MaxDefinitions.*;
import static me.bechberger.ebpf.runtime.MayDefinitions.*;
import static me.bechberger.ebpf.runtime.MaybeDefinitions.*;
import static me.bechberger.ebpf.runtime.MbDefinitions.*;
import static me.bechberger.ebpf.runtime.MbmDefinitions.*;
import static me.bechberger.ebpf.runtime.MboxDefinitions.*;
import static me.bechberger.ebpf.runtime.MceDefinitions.*;
import static me.bechberger.ebpf.runtime.McheckDefinitions.*;
import static me.bechberger.ebpf.runtime.MciDefinitions.*;
import static me.bechberger.ebpf.runtime.MctpDefinitions.*;
import static me.bechberger.ebpf.runtime.MctrlDefinitions.*;
import static me.bechberger.ebpf.runtime.MdDefinitions.*;
import static me.bechberger.ebpf.runtime.MddevDefinitions.*;
import static me.bechberger.ebpf.runtime.MdioDefinitions.*;
import static me.bechberger.ebpf.runtime.MdiobusDefinitions.*;
import static me.bechberger.ebpf.runtime.MemDefinitions.*;
import static me.bechberger.ebpf.runtime.MemblockDefinitions.*;
import static me.bechberger.ebpf.runtime.MemcgDefinitions.*;
import static me.bechberger.ebpf.runtime.MemcpyDefinitions.*;
import static me.bechberger.ebpf.runtime.MemmapDefinitions.*;
import static me.bechberger.ebpf.runtime.MemoryDefinitions.*;
import static me.bechberger.ebpf.runtime.MempoolDefinitions.*;
import static me.bechberger.ebpf.runtime.MemtypeDefinitions.*;
import static me.bechberger.ebpf.runtime.MigrateDefinitions.*;
import static me.bechberger.ebpf.runtime.MinDefinitions.*;
import static me.bechberger.ebpf.runtime.MipiDefinitions.*;
import static me.bechberger.ebpf.runtime.MiscDefinitions.*;
import static me.bechberger.ebpf.runtime.MldDefinitions.*;
import static me.bechberger.ebpf.runtime.MlsDefinitions.*;
import static me.bechberger.ebpf.runtime.MmDefinitions.*;
import static me.bechberger.ebpf.runtime.MmapDefinitions.*;
import static me.bechberger.ebpf.runtime.MmcDefinitions.*;
import static me.bechberger.ebpf.runtime.MmioDefinitions.*;
import static me.bechberger.ebpf.runtime.MmuDefinitions.*;
import static me.bechberger.ebpf.runtime.MntDefinitions.*;
import static me.bechberger.ebpf.runtime.ModDefinitions.*;
import static me.bechberger.ebpf.runtime.ModuleDefinitions.*;
import static me.bechberger.ebpf.runtime.MountDefinitions.*;
import static me.bechberger.ebpf.runtime.MousedevDefinitions.*;
import static me.bechberger.ebpf.runtime.MoveDefinitions.*;
import static me.bechberger.ebpf.runtime.MpDefinitions.*;
import static me.bechberger.ebpf.runtime.MpageDefinitions.*;
import static me.bechberger.ebpf.runtime.MpiDefinitions.*;
import static me.bechberger.ebpf.runtime.MpihelpDefinitions.*;
import static me.bechberger.ebpf.runtime.MpolDefinitions.*;
import static me.bechberger.ebpf.runtime.MptcpDefinitions.*;
import static me.bechberger.ebpf.runtime.MqDefinitions.*;
import static me.bechberger.ebpf.runtime.MqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.MrDefinitions.*;
import static me.bechberger.ebpf.runtime.MsgDefinitions.*;
import static me.bechberger.ebpf.runtime.MsiDefinitions.*;
import static me.bechberger.ebpf.runtime.MsrDefinitions.*;
import static me.bechberger.ebpf.runtime.MtDefinitions.*;
import static me.bechberger.ebpf.runtime.MtreeDefinitions.*;
import static me.bechberger.ebpf.runtime.MtrrDefinitions.*;
import static me.bechberger.ebpf.runtime.MutexDefinitions.*;
import static me.bechberger.ebpf.runtime.NDefinitions.*;
import static me.bechberger.ebpf.runtime.NapiDefinitions.*;
import static me.bechberger.ebpf.runtime.NativeDefinitions.*;
import static me.bechberger.ebpf.runtime.NbconDefinitions.*;
import static me.bechberger.ebpf.runtime.NcsiDefinitions.*;
import static me.bechberger.ebpf.runtime.NdDefinitions.*;
import static me.bechberger.ebpf.runtime.NdiscDefinitions.*;
import static me.bechberger.ebpf.runtime.NeighDefinitions.*;
import static me.bechberger.ebpf.runtime.NetDefinitions.*;
import static me.bechberger.ebpf.runtime.NetdevDefinitions.*;
import static me.bechberger.ebpf.runtime.NetifDefinitions.*;
import static me.bechberger.ebpf.runtime.NetkitDefinitions.*;
import static me.bechberger.ebpf.runtime.NetlblDefinitions.*;
import static me.bechberger.ebpf.runtime.NetlinkDefinitions.*;
import static me.bechberger.ebpf.runtime.NetnsDefinitions.*;
import static me.bechberger.ebpf.runtime.NetpollDefinitions.*;
import static me.bechberger.ebpf.runtime.NewDefinitions.*;
import static me.bechberger.ebpf.runtime.NextDefinitions.*;
import static me.bechberger.ebpf.runtime.NexthopDefinitions.*;
import static me.bechberger.ebpf.runtime.NfDefinitions.*;
import static me.bechberger.ebpf.runtime.Nfs4Definitions.*;
import static me.bechberger.ebpf.runtime.NfsDefinitions.*;
import static me.bechberger.ebpf.runtime.NhDefinitions.*;
import static me.bechberger.ebpf.runtime.NhmexDefinitions.*;
import static me.bechberger.ebpf.runtime.Nl80211Definitions.*;
import static me.bechberger.ebpf.runtime.NlaDefinitions.*;
import static me.bechberger.ebpf.runtime.NmiDefinitions.*;
import static me.bechberger.ebpf.runtime.NoDefinitions.*;
import static me.bechberger.ebpf.runtime.NodeDefinitions.*;
import static me.bechberger.ebpf.runtime.NoopDefinitions.*;
import static me.bechberger.ebpf.runtime.NotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.NrDefinitions.*;
import static me.bechberger.ebpf.runtime.NsDefinitions.*;
import static me.bechberger.ebpf.runtime.NullDefinitions.*;
import static me.bechberger.ebpf.runtime.NumaDefinitions.*;
import static me.bechberger.ebpf.runtime.NumachipDefinitions.*;
import static me.bechberger.ebpf.runtime.NvdimmDefinitions.*;
import static me.bechberger.ebpf.runtime.NvmemDefinitions.*;
import static me.bechberger.ebpf.runtime.ObjDefinitions.*;
import static me.bechberger.ebpf.runtime.OctepDefinitions.*;
import static me.bechberger.ebpf.runtime.OdDefinitions.*;
import static me.bechberger.ebpf.runtime.OfDefinitions.*;
import static me.bechberger.ebpf.runtime.OhciDefinitions.*;
import static me.bechberger.ebpf.runtime.OldDefinitions.*;
import static me.bechberger.ebpf.runtime.OomDefinitions.*;
import static me.bechberger.ebpf.runtime.OpalDefinitions.*;
import static me.bechberger.ebpf.runtime.OpenDefinitions.*;
import static me.bechberger.ebpf.runtime.OppDefinitions.*;
import static me.bechberger.ebpf.runtime.OsnoiseDefinitions.*;
import static me.bechberger.ebpf.runtime.P4Definitions.*;
import static me.bechberger.ebpf.runtime.PacketDefinitions.*;
import static me.bechberger.ebpf.runtime.PadataDefinitions.*;
import static me.bechberger.ebpf.runtime.PageDefinitions.*;
import static me.bechberger.ebpf.runtime.PagemapDefinitions.*;
import static me.bechberger.ebpf.runtime.PagesDefinitions.*;
import static me.bechberger.ebpf.runtime.PalmasDefinitions.*;
import static me.bechberger.ebpf.runtime.PanelDefinitions.*;
import static me.bechberger.ebpf.runtime.ParamDefinitions.*;
import static me.bechberger.ebpf.runtime.ParseDefinitions.*;
import static me.bechberger.ebpf.runtime.PartDefinitions.*;
import static me.bechberger.ebpf.runtime.PathDefinitions.*;
import static me.bechberger.ebpf.runtime.PcapDefinitions.*;
import static me.bechberger.ebpf.runtime.PccDefinitions.*;
import static me.bechberger.ebpf.runtime.PciDefinitions.*;
import static me.bechberger.ebpf.runtime.PcibiosDefinitions.*;
import static me.bechberger.ebpf.runtime.PcieDefinitions.*;
import static me.bechberger.ebpf.runtime.PciehpDefinitions.*;
import static me.bechberger.ebpf.runtime.PcimDefinitions.*;
import static me.bechberger.ebpf.runtime.PcpuDefinitions.*;
import static me.bechberger.ebpf.runtime.PercpuDefinitions.*;
import static me.bechberger.ebpf.runtime.PerfDefinitions.*;
import static me.bechberger.ebpf.runtime.PfifoDefinitions.*;
import static me.bechberger.ebpf.runtime.PfnDefinitions.*;
import static me.bechberger.ebpf.runtime.PhyDefinitions.*;
import static me.bechberger.ebpf.runtime.PhysDefinitions.*;
import static me.bechberger.ebpf.runtime.PhysdevDefinitions.*;
import static me.bechberger.ebpf.runtime.PickDefinitions.*;
import static me.bechberger.ebpf.runtime.PidDefinitions.*;
import static me.bechberger.ebpf.runtime.PidfsDefinitions.*;
import static me.bechberger.ebpf.runtime.PidsDefinitions.*;
import static me.bechberger.ebpf.runtime.PiixDefinitions.*;
import static me.bechberger.ebpf.runtime.PinDefinitions.*;
import static me.bechberger.ebpf.runtime.PinconfDefinitions.*;
import static me.bechberger.ebpf.runtime.PinctrlDefinitions.*;
import static me.bechberger.ebpf.runtime.PingDefinitions.*;
import static me.bechberger.ebpf.runtime.PinmuxDefinitions.*;
import static me.bechberger.ebpf.runtime.PipeDefinitions.*;
import static me.bechberger.ebpf.runtime.PirqDefinitions.*;
import static me.bechberger.ebpf.runtime.Pkcs1padDefinitions.*;
import static me.bechberger.ebpf.runtime.Pkcs7Definitions.*;
import static me.bechberger.ebpf.runtime.PlatformDefinitions.*;
import static me.bechberger.ebpf.runtime.PldmfwDefinitions.*;
import static me.bechberger.ebpf.runtime.Pm860xDefinitions.*;
import static me.bechberger.ebpf.runtime.PmDefinitions.*;
import static me.bechberger.ebpf.runtime.PmcDefinitions.*;
import static me.bechberger.ebpf.runtime.PmdDefinitions.*;
import static me.bechberger.ebpf.runtime.PmuDefinitions.*;
import static me.bechberger.ebpf.runtime.PnpDefinitions.*;
import static me.bechberger.ebpf.runtime.PnpacpiDefinitions.*;
import static me.bechberger.ebpf.runtime.PolicyDefinitions.*;
import static me.bechberger.ebpf.runtime.PolicydbDefinitions.*;
import static me.bechberger.ebpf.runtime.PollDefinitions.*;
import static me.bechberger.ebpf.runtime.Poly1305Definitions.*;
import static me.bechberger.ebpf.runtime.PopulateDefinitions.*;
import static me.bechberger.ebpf.runtime.PortDefinitions.*;
import static me.bechberger.ebpf.runtime.PosixDefinitions.*;
import static me.bechberger.ebpf.runtime.PowerDefinitions.*;
import static me.bechberger.ebpf.runtime.PowercapDefinitions.*;
import static me.bechberger.ebpf.runtime.PppDefinitions.*;
import static me.bechberger.ebpf.runtime.PpsDefinitions.*;
import static me.bechberger.ebpf.runtime.PrDefinitions.*;
import static me.bechberger.ebpf.runtime.PrbDefinitions.*;
import static me.bechberger.ebpf.runtime.PreemptDefinitions.*;
import static me.bechberger.ebpf.runtime.PrepareDefinitions.*;
import static me.bechberger.ebpf.runtime.PrintDefinitions.*;
import static me.bechberger.ebpf.runtime.PrintkDefinitions.*;
import static me.bechberger.ebpf.runtime.ProbeDefinitions.*;
import static me.bechberger.ebpf.runtime.ProbestubDefinitions.*;
import static me.bechberger.ebpf.runtime.ProcDefinitions.*;
import static me.bechberger.ebpf.runtime.ProcessDefinitions.*;
import static me.bechberger.ebpf.runtime.ProfileDefinitions.*;
import static me.bechberger.ebpf.runtime.ProgDefinitions.*;
import static me.bechberger.ebpf.runtime.PropagateDefinitions.*;
import static me.bechberger.ebpf.runtime.ProtoDefinitions.*;
import static me.bechberger.ebpf.runtime.Ps2Definitions.*;
import static me.bechberger.ebpf.runtime.PseDefinitions.*;
import static me.bechberger.ebpf.runtime.PseudoDefinitions.*;
import static me.bechberger.ebpf.runtime.PsiDefinitions.*;
import static me.bechberger.ebpf.runtime.PskbDefinitions.*;
import static me.bechberger.ebpf.runtime.PstoreDefinitions.*;
import static me.bechberger.ebpf.runtime.PtDefinitions.*;
import static me.bechberger.ebpf.runtime.PtdumpDefinitions.*;
import static me.bechberger.ebpf.runtime.PteDefinitions.*;
import static me.bechberger.ebpf.runtime.PtiDefinitions.*;
import static me.bechberger.ebpf.runtime.PtpDefinitions.*;
import static me.bechberger.ebpf.runtime.PtraceDefinitions.*;
import static me.bechberger.ebpf.runtime.PtyDefinitions.*;
import static me.bechberger.ebpf.runtime.PushDefinitions.*;
import static me.bechberger.ebpf.runtime.PutDefinitions.*;
import static me.bechberger.ebpf.runtime.PvDefinitions.*;
import static me.bechberger.ebpf.runtime.PvclockDefinitions.*;
import static me.bechberger.ebpf.runtime.PwmDefinitions.*;
import static me.bechberger.ebpf.runtime.QdiscDefinitions.*;
import static me.bechberger.ebpf.runtime.QhDefinitions.*;
import static me.bechberger.ebpf.runtime.QiDefinitions.*;
import static me.bechberger.ebpf.runtime.QueueDefinitions.*;
import static me.bechberger.ebpf.runtime.QuirkDefinitions.*;
import static me.bechberger.ebpf.runtime.QuotaDefinitions.*;
import static me.bechberger.ebpf.runtime.RadixDefinitions.*;
import static me.bechberger.ebpf.runtime.RamfsDefinitions.*;
import static me.bechberger.ebpf.runtime.RandomDefinitions.*;
import static me.bechberger.ebpf.runtime.RangeDefinitions.*;
import static me.bechberger.ebpf.runtime.Raw6Definitions.*;
import static me.bechberger.ebpf.runtime.RawDefinitions.*;
import static me.bechberger.ebpf.runtime.Rawv6Definitions.*;
import static me.bechberger.ebpf.runtime.RbDefinitions.*;
import static me.bechberger.ebpf.runtime.Rc5t583Definitions.*;
import static me.bechberger.ebpf.runtime.RcuDefinitions.*;
import static me.bechberger.ebpf.runtime.RdevDefinitions.*;
import static me.bechberger.ebpf.runtime.RdmaDefinitions.*;
import static me.bechberger.ebpf.runtime.RdmacgDefinitions.*;
import static me.bechberger.ebpf.runtime.RdtDefinitions.*;
import static me.bechberger.ebpf.runtime.RdtgroupDefinitions.*;
import static me.bechberger.ebpf.runtime.ReadDefinitions.*;
import static me.bechberger.ebpf.runtime.ReclaimDefinitions.*;
import static me.bechberger.ebpf.runtime.RegDefinitions.*;
import static me.bechberger.ebpf.runtime.RegcacheDefinitions.*;
import static me.bechberger.ebpf.runtime.RegisterDefinitions.*;
import static me.bechberger.ebpf.runtime.RegmapDefinitions.*;
import static me.bechberger.ebpf.runtime.RegulatorDefinitions.*;
import static me.bechberger.ebpf.runtime.RelayDefinitions.*;
import static me.bechberger.ebpf.runtime.ReleaseDefinitions.*;
import static me.bechberger.ebpf.runtime.RemapDefinitions.*;
import static me.bechberger.ebpf.runtime.RemoveDefinitions.*;
import static me.bechberger.ebpf.runtime.ReplaceDefinitions.*;
import static me.bechberger.ebpf.runtime.ReportDefinitions.*;
import static me.bechberger.ebpf.runtime.RequestDefinitions.*;
import static me.bechberger.ebpf.runtime.ResctrlDefinitions.*;
import static me.bechberger.ebpf.runtime.ReserveDefinitions.*;
import static me.bechberger.ebpf.runtime.ResetDefinitions.*;
import static me.bechberger.ebpf.runtime.ResourceDefinitions.*;
import static me.bechberger.ebpf.runtime.RestoreDefinitions.*;
import static me.bechberger.ebpf.runtime.RestrictDefinitions.*;
import static me.bechberger.ebpf.runtime.ResumeDefinitions.*;
import static me.bechberger.ebpf.runtime.RethookDefinitions.*;
import static me.bechberger.ebpf.runtime.ReuseportDefinitions.*;
import static me.bechberger.ebpf.runtime.RfkillDefinitions.*;
import static me.bechberger.ebpf.runtime.RhashtableDefinitions.*;
import static me.bechberger.ebpf.runtime.RingDefinitions.*;
import static me.bechberger.ebpf.runtime.RingbufDefinitions.*;
import static me.bechberger.ebpf.runtime.RioDefinitions.*;
import static me.bechberger.ebpf.runtime.RngDefinitions.*;
import static me.bechberger.ebpf.runtime.RoleDefinitions.*;
import static me.bechberger.ebpf.runtime.RpcDefinitions.*;
import static me.bechberger.ebpf.runtime.RpmDefinitions.*;
import static me.bechberger.ebpf.runtime.RprocDefinitions.*;
import static me.bechberger.ebpf.runtime.RqDefinitions.*;
import static me.bechberger.ebpf.runtime.RsaDefinitions.*;
import static me.bechberger.ebpf.runtime.RsassaDefinitions.*;
import static me.bechberger.ebpf.runtime.RseqDefinitions.*;
import static me.bechberger.ebpf.runtime.RssDefinitions.*;
import static me.bechberger.ebpf.runtime.Rt6Definitions.*;
import static me.bechberger.ebpf.runtime.RtDefinitions.*;
import static me.bechberger.ebpf.runtime.RtcDefinitions.*;
import static me.bechberger.ebpf.runtime.RtmDefinitions.*;
import static me.bechberger.ebpf.runtime.RtnetlinkDefinitions.*;
import static me.bechberger.ebpf.runtime.RtnlDefinitions.*;
import static me.bechberger.ebpf.runtime.RunDefinitions.*;
import static me.bechberger.ebpf.runtime.RustDefinitions.*;
import static me.bechberger.ebpf.runtime.RvDefinitions.*;
import static me.bechberger.ebpf.runtime.RxDefinitions.*;
import static me.bechberger.ebpf.runtime.SDefinitions.*;
import static me.bechberger.ebpf.runtime.SataDefinitions.*;
import static me.bechberger.ebpf.runtime.SaveDefinitions.*;
import static me.bechberger.ebpf.runtime.SavedDefinitions.*;
import static me.bechberger.ebpf.runtime.SbitmapDefinitions.*;
import static me.bechberger.ebpf.runtime.ScanDefinitions.*;
import static me.bechberger.ebpf.runtime.SccnxpDefinitions.*;
import static me.bechberger.ebpf.runtime.SchedDefinitions.*;
import static me.bechberger.ebpf.runtime.ScheduleDefinitions.*;
import static me.bechberger.ebpf.runtime.ScmDefinitions.*;
import static me.bechberger.ebpf.runtime.ScsiDefinitions.*;
import static me.bechberger.ebpf.runtime.ScxDefinitions.*;
import static me.bechberger.ebpf.runtime.SdDefinitions.*;
import static me.bechberger.ebpf.runtime.SdevDefinitions.*;
import static me.bechberger.ebpf.runtime.SdioDefinitions.*;
import static me.bechberger.ebpf.runtime.SeccompDefinitions.*;
import static me.bechberger.ebpf.runtime.SecurityDefinitions.*;
import static me.bechberger.ebpf.runtime.Seg6Definitions.*;
import static me.bechberger.ebpf.runtime.SelDefinitions.*;
import static me.bechberger.ebpf.runtime.SelectDefinitions.*;
import static me.bechberger.ebpf.runtime.SelinuxDefinitions.*;
import static me.bechberger.ebpf.runtime.SendDefinitions.*;
import static me.bechberger.ebpf.runtime.SeqDefinitions.*;
import static me.bechberger.ebpf.runtime.SerdevDefinitions.*;
import static me.bechberger.ebpf.runtime.Serial8250Definitions.*;
import static me.bechberger.ebpf.runtime.SerialDefinitions.*;
import static me.bechberger.ebpf.runtime.SerioDefinitions.*;
import static me.bechberger.ebpf.runtime.SetDefinitions.*;
import static me.bechberger.ebpf.runtime.SetupDefinitions.*;
import static me.bechberger.ebpf.runtime.SevDefinitions.*;
import static me.bechberger.ebpf.runtime.SfpDefinitions.*;
import static me.bechberger.ebpf.runtime.SgDefinitions.*;
import static me.bechberger.ebpf.runtime.SgxDefinitions.*;
import static me.bechberger.ebpf.runtime.Sha1Definitions.*;
import static me.bechberger.ebpf.runtime.Sha256Definitions.*;
import static me.bechberger.ebpf.runtime.Sha512Definitions.*;
import static me.bechberger.ebpf.runtime.ShashDefinitions.*;
import static me.bechberger.ebpf.runtime.ShmDefinitions.*;
import static me.bechberger.ebpf.runtime.ShmemDefinitions.*;
import static me.bechberger.ebpf.runtime.ShouldDefinitions.*;
import static me.bechberger.ebpf.runtime.ShowDefinitions.*;
import static me.bechberger.ebpf.runtime.ShpchpDefinitions.*;
import static me.bechberger.ebpf.runtime.ShrinkDefinitions.*;
import static me.bechberger.ebpf.runtime.SidtabDefinitions.*;
import static me.bechberger.ebpf.runtime.SimpleDefinitions.*;
import static me.bechberger.ebpf.runtime.SingleDefinitions.*;
import static me.bechberger.ebpf.runtime.SisDefinitions.*;
import static me.bechberger.ebpf.runtime.SkDefinitions.*;
import static me.bechberger.ebpf.runtime.SkbDefinitions.*;
import static me.bechberger.ebpf.runtime.SkcipherDefinitions.*;
import static me.bechberger.ebpf.runtime.SkxDefinitions.*;
import static me.bechberger.ebpf.runtime.SlabDefinitions.*;
import static me.bechberger.ebpf.runtime.SmackDefinitions.*;
import static me.bechberger.ebpf.runtime.SmeDefinitions.*;
import static me.bechberger.ebpf.runtime.SmkDefinitions.*;
import static me.bechberger.ebpf.runtime.SmpDefinitions.*;
import static me.bechberger.ebpf.runtime.SnapshotDefinitions.*;
import static me.bechberger.ebpf.runtime.SnbDefinitions.*;
import static me.bechberger.ebpf.runtime.SnbepDefinitions.*;
import static me.bechberger.ebpf.runtime.SnpDefinitions.*;
import static me.bechberger.ebpf.runtime.SnrDefinitions.*;
import static me.bechberger.ebpf.runtime.SocDefinitions.*;
import static me.bechberger.ebpf.runtime.SockDefinitions.*;
import static me.bechberger.ebpf.runtime.SoftwareDefinitions.*;
import static me.bechberger.ebpf.runtime.SparseDefinitions.*;
import static me.bechberger.ebpf.runtime.SpiDefinitions.*;
import static me.bechberger.ebpf.runtime.SpliceDefinitions.*;
import static me.bechberger.ebpf.runtime.SplitDefinitions.*;
import static me.bechberger.ebpf.runtime.SprDefinitions.*;
import static me.bechberger.ebpf.runtime.SquashfsDefinitions.*;
import static me.bechberger.ebpf.runtime.SrDefinitions.*;
import static me.bechberger.ebpf.runtime.SramDefinitions.*;
import static me.bechberger.ebpf.runtime.SrcuDefinitions.*;
import static me.bechberger.ebpf.runtime.SriovDefinitions.*;
import static me.bechberger.ebpf.runtime.StackDefinitions.*;
import static me.bechberger.ebpf.runtime.StartDefinitions.*;
import static me.bechberger.ebpf.runtime.StatDefinitions.*;
import static me.bechberger.ebpf.runtime.StaticDefinitions.*;
import static me.bechberger.ebpf.runtime.StatsDefinitions.*;
import static me.bechberger.ebpf.runtime.StopDefinitions.*;
import static me.bechberger.ebpf.runtime.StoreDefinitions.*;
import static me.bechberger.ebpf.runtime.StripeDefinitions.*;
import static me.bechberger.ebpf.runtime.StrpDefinitions.*;
import static me.bechberger.ebpf.runtime.SubflowDefinitions.*;
import static me.bechberger.ebpf.runtime.SubmitDefinitions.*;
import static me.bechberger.ebpf.runtime.SugovDefinitions.*;
import static me.bechberger.ebpf.runtime.SuperDefinitions.*;
import static me.bechberger.ebpf.runtime.SuspendDefinitions.*;
import static me.bechberger.ebpf.runtime.SvcDefinitions.*;
import static me.bechberger.ebpf.runtime.SvsmDefinitions.*;
import static me.bechberger.ebpf.runtime.SwDefinitions.*;
import static me.bechberger.ebpf.runtime.SwapDefinitions.*;
import static me.bechberger.ebpf.runtime.SwiotlbDefinitions.*;
import static me.bechberger.ebpf.runtime.SwitchDefinitions.*;
import static me.bechberger.ebpf.runtime.SwitchdevDefinitions.*;
import static me.bechberger.ebpf.runtime.SwsuspDefinitions.*;
import static me.bechberger.ebpf.runtime.Sx150xDefinitions.*;
import static me.bechberger.ebpf.runtime.SyncDefinitions.*;
import static me.bechberger.ebpf.runtime.SynchronizeDefinitions.*;
import static me.bechberger.ebpf.runtime.SynthDefinitions.*;
import static me.bechberger.ebpf.runtime.SysDefinitions.*;
import static me.bechberger.ebpf.runtime.SyscallDefinitions.*;
import static me.bechberger.ebpf.runtime.SysctlDefinitions.*;
import static me.bechberger.ebpf.runtime.SysfsDefinitions.*;
import static me.bechberger.ebpf.runtime.SysrqDefinitions.*;
import static me.bechberger.ebpf.runtime.SystemDefinitions.*;
import static me.bechberger.ebpf.runtime.SysvecDefinitions.*;
import static me.bechberger.ebpf.runtime.TargetDefinitions.*;
import static me.bechberger.ebpf.runtime.TaskDefinitions.*;
import static me.bechberger.ebpf.runtime.TaskletDefinitions.*;
import static me.bechberger.ebpf.runtime.TbootDefinitions.*;
import static me.bechberger.ebpf.runtime.TcDefinitions.*;
import static me.bechberger.ebpf.runtime.TcfDefinitions.*;
import static me.bechberger.ebpf.runtime.TcpDefinitions.*;
import static me.bechberger.ebpf.runtime.TcxDefinitions.*;
import static me.bechberger.ebpf.runtime.TdhDefinitions.*;
import static me.bechberger.ebpf.runtime.TdxDefinitions.*;
import static me.bechberger.ebpf.runtime.TestDefinitions.*;
import static me.bechberger.ebpf.runtime.TextDefinitions.*;
import static me.bechberger.ebpf.runtime.TgDefinitions.*;
import static me.bechberger.ebpf.runtime.ThermalDefinitions.*;
import static me.bechberger.ebpf.runtime.ThreadDefinitions.*;
import static me.bechberger.ebpf.runtime.ThrotlDefinitions.*;
import static me.bechberger.ebpf.runtime.TickDefinitions.*;
import static me.bechberger.ebpf.runtime.TimekeepingDefinitions.*;
import static me.bechberger.ebpf.runtime.TimensDefinitions.*;
import static me.bechberger.ebpf.runtime.TimerDefinitions.*;
import static me.bechberger.ebpf.runtime.TimerfdDefinitions.*;
import static me.bechberger.ebpf.runtime.TimerlatDefinitions.*;
import static me.bechberger.ebpf.runtime.TkDefinitions.*;
import static me.bechberger.ebpf.runtime.TlbDefinitions.*;
import static me.bechberger.ebpf.runtime.TlsDefinitions.*;
import static me.bechberger.ebpf.runtime.TmigrDefinitions.*;
import static me.bechberger.ebpf.runtime.TnumDefinitions.*;
import static me.bechberger.ebpf.runtime.ToDefinitions.*;
import static me.bechberger.ebpf.runtime.TomoyoDefinitions.*;
import static me.bechberger.ebpf.runtime.TopologyDefinitions.*;
import static me.bechberger.ebpf.runtime.TouchDefinitions.*;
import static me.bechberger.ebpf.runtime.TpacketDefinitions.*;
import static me.bechberger.ebpf.runtime.Tpm1Definitions.*;
import static me.bechberger.ebpf.runtime.Tpm2Definitions.*;
import static me.bechberger.ebpf.runtime.TpmDefinitions.*;
import static me.bechberger.ebpf.runtime.Tps6586xDefinitions.*;
import static me.bechberger.ebpf.runtime.Tps65910Definitions.*;
import static me.bechberger.ebpf.runtime.TraceDefinitions.*;
import static me.bechberger.ebpf.runtime.TracefsDefinitions.*;
import static me.bechberger.ebpf.runtime.TraceiterDefinitions.*;
import static me.bechberger.ebpf.runtime.TracepointDefinitions.*;
import static me.bechberger.ebpf.runtime.TraceprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.TracerDefinitions.*;
import static me.bechberger.ebpf.runtime.TracingDefinitions.*;
import static me.bechberger.ebpf.runtime.TransportDefinitions.*;
import static me.bechberger.ebpf.runtime.TrieDefinitions.*;
import static me.bechberger.ebpf.runtime.TruncateDefinitions.*;
import static me.bechberger.ebpf.runtime.TrustedDefinitions.*;
import static me.bechberger.ebpf.runtime.TryDefinitions.*;
import static me.bechberger.ebpf.runtime.TscDefinitions.*;
import static me.bechberger.ebpf.runtime.TtyDefinitions.*;
import static me.bechberger.ebpf.runtime.TtyportDefinitions.*;
import static me.bechberger.ebpf.runtime.TunDefinitions.*;
import static me.bechberger.ebpf.runtime.Twl4030Definitions.*;
import static me.bechberger.ebpf.runtime.Twl6040Definitions.*;
import static me.bechberger.ebpf.runtime.TwlDefinitions.*;
import static me.bechberger.ebpf.runtime.TxDefinitions.*;
import static me.bechberger.ebpf.runtime.TypeDefinitions.*;
import static me.bechberger.ebpf.runtime.UDefinitions.*;
import static me.bechberger.ebpf.runtime.UartDefinitions.*;
import static me.bechberger.ebpf.runtime.UbsanDefinitions.*;
import static me.bechberger.ebpf.runtime.Udp4Definitions.*;
import static me.bechberger.ebpf.runtime.Udp6Definitions.*;
import static me.bechberger.ebpf.runtime.UdpDefinitions.*;
import static me.bechberger.ebpf.runtime.Udpv6Definitions.*;
import static me.bechberger.ebpf.runtime.UhciDefinitions.*;
import static me.bechberger.ebpf.runtime.UinputDefinitions.*;
import static me.bechberger.ebpf.runtime.UncoreDefinitions.*;
import static me.bechberger.ebpf.runtime.Univ8250Definitions.*;
import static me.bechberger.ebpf.runtime.UnixDefinitions.*;
import static me.bechberger.ebpf.runtime.UnlockDefinitions.*;
import static me.bechberger.ebpf.runtime.UnmapDefinitions.*;
import static me.bechberger.ebpf.runtime.UnregisterDefinitions.*;
import static me.bechberger.ebpf.runtime.UpdateDefinitions.*;
import static me.bechberger.ebpf.runtime.UprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.UsbDefinitions.*;
import static me.bechberger.ebpf.runtime.UsbdevfsDefinitions.*;
import static me.bechberger.ebpf.runtime.UserDefinitions.*;
import static me.bechberger.ebpf.runtime.UserfaultfdDefinitions.*;
import static me.bechberger.ebpf.runtime.Utf8Definitions.*;
import static me.bechberger.ebpf.runtime.UvDefinitions.*;
import static me.bechberger.ebpf.runtime.UvhDefinitions.*;
import static me.bechberger.ebpf.runtime.ValidateDefinitions.*;
import static me.bechberger.ebpf.runtime.VcDefinitions.*;
import static me.bechberger.ebpf.runtime.VcapDefinitions.*;
import static me.bechberger.ebpf.runtime.VcpuDefinitions.*;
import static me.bechberger.ebpf.runtime.VcsDefinitions.*;
import static me.bechberger.ebpf.runtime.VdsoDefinitions.*;
import static me.bechberger.ebpf.runtime.VerifyDefinitions.*;
import static me.bechberger.ebpf.runtime.VfatDefinitions.*;
import static me.bechberger.ebpf.runtime.VfsDefinitions.*;
import static me.bechberger.ebpf.runtime.VgaDefinitions.*;
import static me.bechberger.ebpf.runtime.VgaconDefinitions.*;
import static me.bechberger.ebpf.runtime.ViaDefinitions.*;
import static me.bechberger.ebpf.runtime.ViommuDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtblkDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtioDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtnetDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtscsiDefinitions.*;
import static me.bechberger.ebpf.runtime.VlanDefinitions.*;
import static me.bechberger.ebpf.runtime.VliDefinitions.*;
import static me.bechberger.ebpf.runtime.VmDefinitions.*;
import static me.bechberger.ebpf.runtime.VmaDefinitions.*;
import static me.bechberger.ebpf.runtime.VmallocDefinitions.*;
import static me.bechberger.ebpf.runtime.VmapDefinitions.*;
import static me.bechberger.ebpf.runtime.VmeDefinitions.*;
import static me.bechberger.ebpf.runtime.VmemmapDefinitions.*;
import static me.bechberger.ebpf.runtime.VmpressureDefinitions.*;
import static me.bechberger.ebpf.runtime.VmstatDefinitions.*;
import static me.bechberger.ebpf.runtime.VmwareDefinitions.*;
import static me.bechberger.ebpf.runtime.VpDefinitions.*;
import static me.bechberger.ebpf.runtime.VringDefinitions.*;
import static me.bechberger.ebpf.runtime.VtDefinitions.*;
import static me.bechberger.ebpf.runtime.WaitDefinitions.*;
import static me.bechberger.ebpf.runtime.WakeDefinitions.*;
import static me.bechberger.ebpf.runtime.WakeupDefinitions.*;
import static me.bechberger.ebpf.runtime.WalkDefinitions.*;
import static me.bechberger.ebpf.runtime.WarnDefinitions.*;
import static me.bechberger.ebpf.runtime.WatchDefinitions.*;
import static me.bechberger.ebpf.runtime.WatchdogDefinitions.*;
import static me.bechberger.ebpf.runtime.WbDefinitions.*;
import static me.bechberger.ebpf.runtime.WbtDefinitions.*;
import static me.bechberger.ebpf.runtime.WiphyDefinitions.*;
import static me.bechberger.ebpf.runtime.WirelessDefinitions.*;
import static me.bechberger.ebpf.runtime.Wm831xDefinitions.*;
import static me.bechberger.ebpf.runtime.Wm8350Definitions.*;
import static me.bechberger.ebpf.runtime.WorkqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.WpDefinitions.*;
import static me.bechberger.ebpf.runtime.WqDefinitions.*;
import static me.bechberger.ebpf.runtime.WriteDefinitions.*;
import static me.bechberger.ebpf.runtime.WritebackDefinitions.*;
import static me.bechberger.ebpf.runtime.WwDefinitions.*;
import static me.bechberger.ebpf.runtime.X2apicDefinitions.*;
import static me.bechberger.ebpf.runtime.X509Definitions.*;
import static me.bechberger.ebpf.runtime.X64Definitions.*;
import static me.bechberger.ebpf.runtime.X86Definitions.*;
import static me.bechberger.ebpf.runtime.XaDefinitions.*;
import static me.bechberger.ebpf.runtime.XasDefinitions.*;
import static me.bechberger.ebpf.runtime.XattrDefinitions.*;
import static me.bechberger.ebpf.runtime.XbcDefinitions.*;
import static me.bechberger.ebpf.runtime.XdbcDefinitions.*;
import static me.bechberger.ebpf.runtime.XdpDefinitions.*;
import static me.bechberger.ebpf.runtime.XenDefinitions.*;
import static me.bechberger.ebpf.runtime.XenbusDefinitions.*;
import static me.bechberger.ebpf.runtime.XennetDefinitions.*;
import static me.bechberger.ebpf.runtime.XenpfDefinitions.*;
import static me.bechberger.ebpf.runtime.Xfrm4Definitions.*;
import static me.bechberger.ebpf.runtime.Xfrm6Definitions.*;
import static me.bechberger.ebpf.runtime.XfrmDefinitions.*;
import static me.bechberger.ebpf.runtime.XhciDefinitions.*;
import static me.bechberger.ebpf.runtime.XpDefinitions.*;
import static me.bechberger.ebpf.runtime.XsDefinitions.*;
import static me.bechberger.ebpf.runtime.XskDefinitions.*;
import static me.bechberger.ebpf.runtime.XtsDefinitions.*;
import static me.bechberger.ebpf.runtime.XzDefinitions.*;
import static me.bechberger.ebpf.runtime.ZapDefinitions.*;
import static me.bechberger.ebpf.runtime.ZlibDefinitions.*;
import static me.bechberger.ebpf.runtime.ZoneDefinitions.*;
import static me.bechberger.ebpf.runtime.ZpoolDefinitions.*;
import static me.bechberger.ebpf.runtime.ZsDefinitions.*;
import static me.bechberger.ebpf.runtime.ZstdDefinitions.*;
import static me.bechberger.ebpf.runtime.ZswapDefinitions.*;
import static me.bechberger.ebpf.runtime.misc.*;
import static me.bechberger.ebpf.runtime.runtime.*;

/**
 * Generated class for BPF runtime types that start with sctp
 */
@java.lang.SuppressWarnings("unused")
public final class SctpDefinitions {
  @Type(
      noCCodeGeneration = true,
      cType = "enum sctp_conntrack"
  )
  public enum sctp_conntrack implements Enum<sctp_conntrack>, TypedEnum<sctp_conntrack, java.lang. @Unsigned Integer> {
    /**
     * {@code SCTP_CONNTRACK_NONE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "SCTP_CONNTRACK_NONE"
    )
    SCTP_CONNTRACK_NONE,

    /**
     * {@code SCTP_CONNTRACK_CLOSED = 1}
     */
    @EnumMember(
        value = 1L,
        name = "SCTP_CONNTRACK_CLOSED"
    )
    SCTP_CONNTRACK_CLOSED,

    /**
     * {@code SCTP_CONNTRACK_COOKIE_WAIT = 2}
     */
    @EnumMember(
        value = 2L,
        name = "SCTP_CONNTRACK_COOKIE_WAIT"
    )
    SCTP_CONNTRACK_COOKIE_WAIT,

    /**
     * {@code SCTP_CONNTRACK_COOKIE_ECHOED = 3}
     */
    @EnumMember(
        value = 3L,
        name = "SCTP_CONNTRACK_COOKIE_ECHOED"
    )
    SCTP_CONNTRACK_COOKIE_ECHOED,

    /**
     * {@code SCTP_CONNTRACK_ESTABLISHED = 4}
     */
    @EnumMember(
        value = 4L,
        name = "SCTP_CONNTRACK_ESTABLISHED"
    )
    SCTP_CONNTRACK_ESTABLISHED,

    /**
     * {@code SCTP_CONNTRACK_SHUTDOWN_SENT = 5}
     */
    @EnumMember(
        value = 5L,
        name = "SCTP_CONNTRACK_SHUTDOWN_SENT"
    )
    SCTP_CONNTRACK_SHUTDOWN_SENT,

    /**
     * {@code SCTP_CONNTRACK_SHUTDOWN_RECD = 6}
     */
    @EnumMember(
        value = 6L,
        name = "SCTP_CONNTRACK_SHUTDOWN_RECD"
    )
    SCTP_CONNTRACK_SHUTDOWN_RECD,

    /**
     * {@code SCTP_CONNTRACK_SHUTDOWN_ACK_SENT = 7}
     */
    @EnumMember(
        value = 7L,
        name = "SCTP_CONNTRACK_SHUTDOWN_ACK_SENT"
    )
    SCTP_CONNTRACK_SHUTDOWN_ACK_SENT,

    /**
     * {@code SCTP_CONNTRACK_HEARTBEAT_SENT = 8}
     */
    @EnumMember(
        value = 8L,
        name = "SCTP_CONNTRACK_HEARTBEAT_SENT"
    )
    SCTP_CONNTRACK_HEARTBEAT_SENT,

    /**
     * {@code SCTP_CONNTRACK_HEARTBEAT_ACKED = 9}
     */
    @EnumMember(
        value = 9L,
        name = "SCTP_CONNTRACK_HEARTBEAT_ACKED"
    )
    SCTP_CONNTRACK_HEARTBEAT_ACKED,

    /**
     * {@code SCTP_CONNTRACK_MAX = 10}
     */
    @EnumMember(
        value = 10L,
        name = "SCTP_CONNTRACK_MAX"
    )
    SCTP_CONNTRACK_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct sctp_association"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class sctp_association extends Struct {
    public sctp_ep_common base;

    public list_head asocs;

    public @OriginalName("sctp_assoc_t") int assoc_id;

    public Ptr<sctp_endpoint> ep;

    public sctp_cookie c;

    public peer_of_sctp_association peer;

    public sctp_state state;

    public int overall_error_count;

    public @OriginalName("ktime_t") long cookie_life;

    public @Unsigned long rto_initial;

    public @Unsigned long rto_max;

    public @Unsigned long rto_min;

    public int max_burst;

    public int max_retrans;

    public @Unsigned short pf_retrans;

    public @Unsigned short ps_retrans;

    public @Unsigned short max_init_attempts;

    public @Unsigned short init_retries;

    public @Unsigned long max_init_timeo;

    public @Unsigned long hbinterval;

    public @Unsigned long probe_interval;

    public @Unsigned @OriginalName("__be16") short encap_port;

    public @Unsigned short pathmaxrxt;

    public @Unsigned int flowlabel;

    public char dscp;

    public char pmtu_pending;

    public @Unsigned int pathmtu;

    public @Unsigned int param_flags;

    public @Unsigned int sackfreq;

    public @Unsigned long sackdelay;

    public @Unsigned long @Size(12) [] timeouts;

    public timer_list @Size(12) [] timers;

    public Ptr<sctp_transport> shutdown_last_sent_to;

    public Ptr<sctp_transport> init_last_sent_to;

    public int shutdown_retries;

    public @Unsigned int next_tsn;

    public @Unsigned int ctsn_ack_point;

    public @Unsigned int adv_peer_ack_point;

    public @Unsigned int highest_sacked;

    public @Unsigned int fast_recovery_exit;

    public char fast_recovery;

    public @Unsigned short unack_data;

    public @Unsigned int rtx_data_chunks;

    public @Unsigned int rwnd;

    public @Unsigned int a_rwnd;

    public @Unsigned int rwnd_over;

    public @Unsigned int rwnd_press;

    public int sndbuf_used;

    public atomic_t rmem_alloc;

    public @OriginalName("wait_queue_head_t") wait_queue_head wait;

    public @Unsigned int frag_point;

    public @Unsigned int user_frag;

    public int init_err_counter;

    public int init_cycle;

    public @Unsigned short default_stream;

    public @Unsigned short default_flags;

    public @Unsigned int default_ppid;

    public @Unsigned int default_context;

    public @Unsigned int default_timetolive;

    public @Unsigned int default_rcv_context;

    public sctp_stream stream;

    public sctp_outq outqueue;

    public sctp_ulpq ulpq;

    public @Unsigned int last_ecne_tsn;

    public @Unsigned int last_cwr_tsn;

    public int numduptsns;

    public Ptr<sctp_chunk> addip_last_asconf;

    public list_head asconf_ack_list;

    public list_head addip_chunk_list;

    public @Unsigned int addip_serial;

    public int src_out_of_asoc_ok;

    public Ptr<sctp_addr> asconf_addr_del_pending;

    public Ptr<sctp_transport> new_transport;

    public list_head endpoint_shared_keys;

    public Ptr<sctp_auth_bytes> asoc_shared_key;

    public Ptr<sctp_shared_key> shkey;

    public @Unsigned short default_hmac_id;

    public @Unsigned short active_key_id;

    public char need_ecne;

    public char temp;

    public char pf_expose;

    public char force_delay;

    public char strreset_enable;

    public char strreset_outstanding;

    public @Unsigned int strreset_outseq;

    public @Unsigned int strreset_inseq;

    public @Unsigned int @Size(2) [] strreset_result;

    public Ptr<sctp_chunk> strreset_chunk;

    public sctp_priv_assoc_stats stats;

    public int sent_cnt_removable;

    public @Unsigned short subscribe;

    public @Unsigned long @Size(3) [] abandoned_unsent;

    public @Unsigned long @Size(3) [] abandoned_sent;

    public @Unsigned int secid;

    public @Unsigned int peer_secid;

    public callback_head rcu;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum sctp_msg_flags"
  )
  public enum sctp_msg_flags implements Enum<sctp_msg_flags>, TypedEnum<sctp_msg_flags, java.lang. @Unsigned Integer> {
    /**
     * {@code MSG_NOTIFICATION = 32768}
     */
    @EnumMember(
        value = 32768L,
        name = "MSG_NOTIFICATION"
    )
    MSG_NOTIFICATION
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct sctp_initmsg"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class sctp_initmsg extends Struct {
    public @Unsigned short sinit_num_ostreams;

    public @Unsigned short sinit_max_instreams;

    public @Unsigned short sinit_max_attempts;

    public @Unsigned short sinit_max_init_timeo;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct sctp_sndrcvinfo"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class sctp_sndrcvinfo extends Struct {
    public @Unsigned short sinfo_stream;

    public @Unsigned short sinfo_ssn;

    public @Unsigned short sinfo_flags;

    public @Unsigned int sinfo_ppid;

    public @Unsigned int sinfo_context;

    public @Unsigned int sinfo_timetolive;

    public @Unsigned int sinfo_tsn;

    public @Unsigned int sinfo_cumtsn;

    public @OriginalName("sctp_assoc_t") int sinfo_assoc_id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct sctp_rtoinfo"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class sctp_rtoinfo extends Struct {
    public @OriginalName("sctp_assoc_t") int srto_assoc_id;

    public @Unsigned int srto_initial;

    public @Unsigned int srto_max;

    public @Unsigned int srto_min;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct sctp_assocparams"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class sctp_assocparams extends Struct {
    public @OriginalName("sctp_assoc_t") int sasoc_assoc_id;

    public @Unsigned short sasoc_asocmaxrxt;

    public @Unsigned short sasoc_number_peer_destinations;

    public @Unsigned int sasoc_peer_rwnd;

    public @Unsigned int sasoc_local_rwnd;

    public @Unsigned int sasoc_cookie_life;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct sctp_paddrparams"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class sctp_paddrparams extends Struct {
    public @OriginalName("sctp_assoc_t") int spp_assoc_id;

    public __kernel_sockaddr_storage spp_address;

    public @Unsigned int spp_hbinterval;

    public @Unsigned short spp_pathmaxrxt;

    public @Unsigned int spp_pathmtu;

    public @Unsigned int spp_sackdelay;

    public @Unsigned int spp_flags;

    public @Unsigned int spp_ipv6_flowlabel;

    public char spp_dscp;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct sctp_chunkhdr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class sctp_chunkhdr extends Struct {
    public char type;

    public char flags;

    public @Unsigned @OriginalName("__be16") short length;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum sctp_cid"
  )
  public enum sctp_cid implements Enum<sctp_cid>, TypedEnum<sctp_cid, java.lang. @Unsigned Integer> {
    /**
     * {@code SCTP_CID_DATA = 0}
     */
    @EnumMember(
        value = 0L,
        name = "SCTP_CID_DATA"
    )
    SCTP_CID_DATA,

    /**
     * {@code SCTP_CID_INIT = 1}
     */
    @EnumMember(
        value = 1L,
        name = "SCTP_CID_INIT"
    )
    SCTP_CID_INIT,

    /**
     * {@code SCTP_CID_INIT_ACK = 2}
     */
    @EnumMember(
        value = 2L,
        name = "SCTP_CID_INIT_ACK"
    )
    SCTP_CID_INIT_ACK,

    /**
     * {@code SCTP_CID_SACK = 3}
     */
    @EnumMember(
        value = 3L,
        name = "SCTP_CID_SACK"
    )
    SCTP_CID_SACK,

    /**
     * {@code SCTP_CID_HEARTBEAT = 4}
     */
    @EnumMember(
        value = 4L,
        name = "SCTP_CID_HEARTBEAT"
    )
    SCTP_CID_HEARTBEAT,

    /**
     * {@code SCTP_CID_HEARTBEAT_ACK = 5}
     */
    @EnumMember(
        value = 5L,
        name = "SCTP_CID_HEARTBEAT_ACK"
    )
    SCTP_CID_HEARTBEAT_ACK,

    /**
     * {@code SCTP_CID_ABORT = 6}
     */
    @EnumMember(
        value = 6L,
        name = "SCTP_CID_ABORT"
    )
    SCTP_CID_ABORT,

    /**
     * {@code SCTP_CID_SHUTDOWN = 7}
     */
    @EnumMember(
        value = 7L,
        name = "SCTP_CID_SHUTDOWN"
    )
    SCTP_CID_SHUTDOWN,

    /**
     * {@code SCTP_CID_SHUTDOWN_ACK = 8}
     */
    @EnumMember(
        value = 8L,
        name = "SCTP_CID_SHUTDOWN_ACK"
    )
    SCTP_CID_SHUTDOWN_ACK,

    /**
     * {@code SCTP_CID_ERROR = 9}
     */
    @EnumMember(
        value = 9L,
        name = "SCTP_CID_ERROR"
    )
    SCTP_CID_ERROR,

    /**
     * {@code SCTP_CID_COOKIE_ECHO = 10}
     */
    @EnumMember(
        value = 10L,
        name = "SCTP_CID_COOKIE_ECHO"
    )
    SCTP_CID_COOKIE_ECHO,

    /**
     * {@code SCTP_CID_COOKIE_ACK = 11}
     */
    @EnumMember(
        value = 11L,
        name = "SCTP_CID_COOKIE_ACK"
    )
    SCTP_CID_COOKIE_ACK,

    /**
     * {@code SCTP_CID_ECN_ECNE = 12}
     */
    @EnumMember(
        value = 12L,
        name = "SCTP_CID_ECN_ECNE"
    )
    SCTP_CID_ECN_ECNE,

    /**
     * {@code SCTP_CID_ECN_CWR = 13}
     */
    @EnumMember(
        value = 13L,
        name = "SCTP_CID_ECN_CWR"
    )
    SCTP_CID_ECN_CWR,

    /**
     * {@code SCTP_CID_SHUTDOWN_COMPLETE = 14}
     */
    @EnumMember(
        value = 14L,
        name = "SCTP_CID_SHUTDOWN_COMPLETE"
    )
    SCTP_CID_SHUTDOWN_COMPLETE,

    /**
     * {@code SCTP_CID_AUTH = 15}
     */
    @EnumMember(
        value = 15L,
        name = "SCTP_CID_AUTH"
    )
    SCTP_CID_AUTH,

    /**
     * {@code SCTP_CID_I_DATA = 64}
     */
    @EnumMember(
        value = 64L,
        name = "SCTP_CID_I_DATA"
    )
    SCTP_CID_I_DATA,

    /**
     * {@code SCTP_CID_FWD_TSN = 192}
     */
    @EnumMember(
        value = 192L,
        name = "SCTP_CID_FWD_TSN"
    )
    SCTP_CID_FWD_TSN,

    /**
     * {@code SCTP_CID_ASCONF = 193}
     */
    @EnumMember(
        value = 193L,
        name = "SCTP_CID_ASCONF"
    )
    SCTP_CID_ASCONF,

    /**
     * {@code SCTP_CID_I_FWD_TSN = 194}
     */
    @EnumMember(
        value = 194L,
        name = "SCTP_CID_I_FWD_TSN"
    )
    SCTP_CID_I_FWD_TSN,

    /**
     * {@code SCTP_CID_ASCONF_ACK = 128}
     */
    @EnumMember(
        value = 128L,
        name = "SCTP_CID_ASCONF_ACK"
    )
    SCTP_CID_ASCONF_ACK,

    /**
     * {@code SCTP_CID_RECONF = 130}
     */
    @EnumMember(
        value = 130L,
        name = "SCTP_CID_RECONF"
    )
    SCTP_CID_RECONF,

    /**
     * {@code SCTP_CID_PAD = 132}
     */
    @EnumMember(
        value = 132L,
        name = "SCTP_CID_PAD"
    )
    SCTP_CID_PAD
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct sctp_paramhdr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class sctp_paramhdr extends Struct {
    public @Unsigned @OriginalName("__be16") short type;

    public @Unsigned @OriginalName("__be16") short length;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum sctp_param"
  )
  public enum sctp_param implements Enum<sctp_param>, TypedEnum<sctp_param, java.lang. @Unsigned Integer> {
    /**
     * {@code SCTP_PARAM_HEARTBEAT_INFO = 256}
     */
    @EnumMember(
        value = 256L,
        name = "SCTP_PARAM_HEARTBEAT_INFO"
    )
    SCTP_PARAM_HEARTBEAT_INFO,

    /**
     * {@code SCTP_PARAM_IPV4_ADDRESS = 1280}
     */
    @EnumMember(
        value = 1280L,
        name = "SCTP_PARAM_IPV4_ADDRESS"
    )
    SCTP_PARAM_IPV4_ADDRESS,

    /**
     * {@code SCTP_PARAM_IPV6_ADDRESS = 1536}
     */
    @EnumMember(
        value = 1536L,
        name = "SCTP_PARAM_IPV6_ADDRESS"
    )
    SCTP_PARAM_IPV6_ADDRESS,

    /**
     * {@code SCTP_PARAM_STATE_COOKIE = 1792}
     */
    @EnumMember(
        value = 1792L,
        name = "SCTP_PARAM_STATE_COOKIE"
    )
    SCTP_PARAM_STATE_COOKIE,

    /**
     * {@code SCTP_PARAM_UNRECOGNIZED_PARAMETERS = 2048}
     */
    @EnumMember(
        value = 2048L,
        name = "SCTP_PARAM_UNRECOGNIZED_PARAMETERS"
    )
    SCTP_PARAM_UNRECOGNIZED_PARAMETERS,

    /**
     * {@code SCTP_PARAM_COOKIE_PRESERVATIVE = 2304}
     */
    @EnumMember(
        value = 2304L,
        name = "SCTP_PARAM_COOKIE_PRESERVATIVE"
    )
    SCTP_PARAM_COOKIE_PRESERVATIVE,

    /**
     * {@code SCTP_PARAM_HOST_NAME_ADDRESS = 2816}
     */
    @EnumMember(
        value = 2816L,
        name = "SCTP_PARAM_HOST_NAME_ADDRESS"
    )
    SCTP_PARAM_HOST_NAME_ADDRESS,

    /**
     * {@code SCTP_PARAM_SUPPORTED_ADDRESS_TYPES = 3072}
     */
    @EnumMember(
        value = 3072L,
        name = "SCTP_PARAM_SUPPORTED_ADDRESS_TYPES"
    )
    SCTP_PARAM_SUPPORTED_ADDRESS_TYPES,

    /**
     * {@code SCTP_PARAM_ECN_CAPABLE = 128}
     */
    @EnumMember(
        value = 128L,
        name = "SCTP_PARAM_ECN_CAPABLE"
    )
    SCTP_PARAM_ECN_CAPABLE,

    /**
     * {@code SCTP_PARAM_RANDOM = 640}
     */
    @EnumMember(
        value = 640L,
        name = "SCTP_PARAM_RANDOM"
    )
    SCTP_PARAM_RANDOM,

    /**
     * {@code SCTP_PARAM_CHUNKS = 896}
     */
    @EnumMember(
        value = 896L,
        name = "SCTP_PARAM_CHUNKS"
    )
    SCTP_PARAM_CHUNKS,

    /**
     * {@code SCTP_PARAM_HMAC_ALGO = 1152}
     */
    @EnumMember(
        value = 1152L,
        name = "SCTP_PARAM_HMAC_ALGO"
    )
    SCTP_PARAM_HMAC_ALGO,

    /**
     * {@code SCTP_PARAM_SUPPORTED_EXT = 2176}
     */
    @EnumMember(
        value = 2176L,
        name = "SCTP_PARAM_SUPPORTED_EXT"
    )
    SCTP_PARAM_SUPPORTED_EXT,

    /**
     * {@code SCTP_PARAM_FWD_TSN_SUPPORT = 192}
     */
    @EnumMember(
        value = 192L,
        name = "SCTP_PARAM_FWD_TSN_SUPPORT"
    )
    SCTP_PARAM_FWD_TSN_SUPPORT,

    /**
     * {@code SCTP_PARAM_ADD_IP = 448}
     */
    @EnumMember(
        value = 448L,
        name = "SCTP_PARAM_ADD_IP"
    )
    SCTP_PARAM_ADD_IP,

    /**
     * {@code SCTP_PARAM_DEL_IP = 704}
     */
    @EnumMember(
        value = 704L,
        name = "SCTP_PARAM_DEL_IP"
    )
    SCTP_PARAM_DEL_IP,

    /**
     * {@code SCTP_PARAM_ERR_CAUSE = 960}
     */
    @EnumMember(
        value = 960L,
        name = "SCTP_PARAM_ERR_CAUSE"
    )
    SCTP_PARAM_ERR_CAUSE,

    /**
     * {@code SCTP_PARAM_SET_PRIMARY = 1216}
     */
    @EnumMember(
        value = 1216L,
        name = "SCTP_PARAM_SET_PRIMARY"
    )
    SCTP_PARAM_SET_PRIMARY,

    /**
     * {@code SCTP_PARAM_SUCCESS_REPORT = 1472}
     */
    @EnumMember(
        value = 1472L,
        name = "SCTP_PARAM_SUCCESS_REPORT"
    )
    SCTP_PARAM_SUCCESS_REPORT,

    /**
     * {@code SCTP_PARAM_ADAPTATION_LAYER_IND = 1728}
     */
    @EnumMember(
        value = 1728L,
        name = "SCTP_PARAM_ADAPTATION_LAYER_IND"
    )
    SCTP_PARAM_ADAPTATION_LAYER_IND,

    /**
     * {@code SCTP_PARAM_RESET_OUT_REQUEST = 3328}
     */
    @EnumMember(
        value = 3328L,
        name = "SCTP_PARAM_RESET_OUT_REQUEST"
    )
    SCTP_PARAM_RESET_OUT_REQUEST,

    /**
     * {@code SCTP_PARAM_RESET_IN_REQUEST = 3584}
     */
    @EnumMember(
        value = 3584L,
        name = "SCTP_PARAM_RESET_IN_REQUEST"
    )
    SCTP_PARAM_RESET_IN_REQUEST,

    /**
     * {@code SCTP_PARAM_RESET_TSN_REQUEST = 3840}
     */
    @EnumMember(
        value = 3840L,
        name = "SCTP_PARAM_RESET_TSN_REQUEST"
    )
    SCTP_PARAM_RESET_TSN_REQUEST,

    /**
     * {@code SCTP_PARAM_RESET_RESPONSE = 4096}
     */
    @EnumMember(
        value = 4096L,
        name = "SCTP_PARAM_RESET_RESPONSE"
    )
    SCTP_PARAM_RESET_RESPONSE,

    /**
     * {@code SCTP_PARAM_RESET_ADD_OUT_STREAMS = 4352}
     */
    @EnumMember(
        value = 4352L,
        name = "SCTP_PARAM_RESET_ADD_OUT_STREAMS"
    )
    SCTP_PARAM_RESET_ADD_OUT_STREAMS,

    /**
     * {@code SCTP_PARAM_RESET_ADD_IN_STREAMS = 4608}
     */
    @EnumMember(
        value = 4608L,
        name = "SCTP_PARAM_RESET_ADD_IN_STREAMS"
    )
    SCTP_PARAM_RESET_ADD_IN_STREAMS
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct sctp_datahdr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class sctp_datahdr extends Struct {
    public @Unsigned @OriginalName("__be32") int tsn;

    public @Unsigned @OriginalName("__be16") short stream;

    public @Unsigned @OriginalName("__be16") short ssn;

    public @Unsigned int ppid;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct sctp_idatahdr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class sctp_idatahdr extends Struct {
    public @Unsigned @OriginalName("__be32") int tsn;

    public @Unsigned @OriginalName("__be16") short stream;

    public @Unsigned @OriginalName("__be16") short reserved;

    public @Unsigned @OriginalName("__be32") int mid;

    @InlineUnion(27753)
    public @Unsigned int ppid;

    @InlineUnion(27753)
    public @Unsigned @OriginalName("__be32") int fsn;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct sctp_inithdr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class sctp_inithdr extends Struct {
    public @Unsigned @OriginalName("__be32") int init_tag;

    public @Unsigned @OriginalName("__be32") int a_rwnd;

    public @Unsigned @OriginalName("__be16") short num_outbound_streams;

    public @Unsigned @OriginalName("__be16") short num_inbound_streams;

    public @Unsigned @OriginalName("__be32") int initial_tsn;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct sctp_ipv4addr_param"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class sctp_ipv4addr_param extends Struct {
    public sctp_paramhdr param_hdr;

    public in_addr addr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct sctp_ipv6addr_param"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class sctp_ipv6addr_param extends Struct {
    public sctp_paramhdr param_hdr;

    public in6_addr addr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct sctp_cookie_preserve_param"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class sctp_cookie_preserve_param extends Struct {
    public sctp_paramhdr param_hdr;

    public @Unsigned @OriginalName("__be32") int lifespan_increment;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct sctp_hostname_param"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class sctp_hostname_param extends Struct {
    public sctp_paramhdr param_hdr;

    public @OriginalName("uint8_t") char @Size(0) [] hostname;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct sctp_supported_addrs_param"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class sctp_supported_addrs_param extends Struct {
    public sctp_paramhdr param_hdr;

    public @Unsigned @OriginalName("__be16") short @Size(0) [] types;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct sctp_adaptation_ind_param"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class sctp_adaptation_ind_param extends Struct {
    public sctp_paramhdr param_hdr;

    public @Unsigned @OriginalName("__be32") int adaptation_ind;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct sctp_supported_ext_param"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class sctp_supported_ext_param extends Struct {
    public sctp_paramhdr param_hdr;

    public char @Size(0) [] chunks;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct sctp_random_param"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class sctp_random_param extends Struct {
    public sctp_paramhdr param_hdr;

    public char @Size(0) [] random_val;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct sctp_chunks_param"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class sctp_chunks_param extends Struct {
    public sctp_paramhdr param_hdr;

    public char @Size(0) [] chunks;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct sctp_hmac_algo_param"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class sctp_hmac_algo_param extends Struct {
    public sctp_paramhdr param_hdr;

    public @Unsigned @OriginalName("__be16") short @Size(0) [] hmac_ids;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct sctp_cookie_param"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class sctp_cookie_param extends Struct {
    public sctp_paramhdr p;

    public char @Size(0) [] body;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct sctp_sackhdr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class sctp_sackhdr extends Struct {
    public @Unsigned @OriginalName("__be32") int cum_tsn_ack;

    public @Unsigned @OriginalName("__be32") int a_rwnd;

    public @Unsigned @OriginalName("__be16") short num_gap_ack_blocks;

    public @Unsigned @OriginalName("__be16") short num_dup_tsns;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct sctp_heartbeathdr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class sctp_heartbeathdr extends Struct {
    public sctp_paramhdr info;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct sctp_shutdownhdr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class sctp_shutdownhdr extends Struct {
    public @Unsigned @OriginalName("__be32") int cum_tsn_ack;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct sctp_errhdr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class sctp_errhdr extends Struct {
    public @Unsigned @OriginalName("__be16") short cause;

    public @Unsigned @OriginalName("__be16") short length;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct sctp_ecnehdr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class sctp_ecnehdr extends Struct {
    public @Unsigned @OriginalName("__be32") int lowest_tsn;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct sctp_cwrhdr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class sctp_cwrhdr extends Struct {
    public @Unsigned @OriginalName("__be32") int lowest_tsn;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct sctp_fwdtsn_hdr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class sctp_fwdtsn_hdr extends Struct {
    public @Unsigned @OriginalName("__be32") int new_cum_tsn;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct sctp_ifwdtsn_hdr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class sctp_ifwdtsn_hdr extends Struct {
    public @Unsigned @OriginalName("__be32") int new_cum_tsn;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct sctp_addip_param"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class sctp_addip_param extends Struct {
    public sctp_paramhdr param_hdr;

    public @Unsigned @OriginalName("__be32") int crr_id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct sctp_addiphdr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class sctp_addiphdr extends Struct {
    public @Unsigned @OriginalName("__be32") int serial;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct sctp_authhdr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class sctp_authhdr extends Struct {
    public @Unsigned @OriginalName("__be16") short shkey_id;

    public @Unsigned @OriginalName("__be16") short hmac_id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct sctp_auth_bytes"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class sctp_auth_bytes extends Struct {
    public @OriginalName("refcount_t") refcount_struct refcnt;

    public @Unsigned int len;

    public char @Size(0) [] data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct sctp_shared_key"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class sctp_shared_key extends Struct {
    public list_head key_list;

    public Ptr<sctp_auth_bytes> key;

    public @OriginalName("refcount_t") refcount_struct refcnt;

    public @Unsigned short key_id;

    public char deactivated;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union sctp_addr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class sctp_addr extends Union {
    public sockaddr_inet sa;

    public sockaddr_in v4;

    public sockaddr_in6 v6;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum sctp_event_timeout"
  )
  public enum sctp_event_timeout implements Enum<sctp_event_timeout>, TypedEnum<sctp_event_timeout, java.lang. @Unsigned Integer> {
    /**
     * {@code SCTP_EVENT_TIMEOUT_NONE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "SCTP_EVENT_TIMEOUT_NONE"
    )
    SCTP_EVENT_TIMEOUT_NONE,

    /**
     * {@code SCTP_EVENT_TIMEOUT_T1_COOKIE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "SCTP_EVENT_TIMEOUT_T1_COOKIE"
    )
    SCTP_EVENT_TIMEOUT_T1_COOKIE,

    /**
     * {@code SCTP_EVENT_TIMEOUT_T1_INIT = 2}
     */
    @EnumMember(
        value = 2L,
        name = "SCTP_EVENT_TIMEOUT_T1_INIT"
    )
    SCTP_EVENT_TIMEOUT_T1_INIT,

    /**
     * {@code SCTP_EVENT_TIMEOUT_T2_SHUTDOWN = 3}
     */
    @EnumMember(
        value = 3L,
        name = "SCTP_EVENT_TIMEOUT_T2_SHUTDOWN"
    )
    SCTP_EVENT_TIMEOUT_T2_SHUTDOWN,

    /**
     * {@code SCTP_EVENT_TIMEOUT_T3_RTX = 4}
     */
    @EnumMember(
        value = 4L,
        name = "SCTP_EVENT_TIMEOUT_T3_RTX"
    )
    SCTP_EVENT_TIMEOUT_T3_RTX,

    /**
     * {@code SCTP_EVENT_TIMEOUT_T4_RTO = 5}
     */
    @EnumMember(
        value = 5L,
        name = "SCTP_EVENT_TIMEOUT_T4_RTO"
    )
    SCTP_EVENT_TIMEOUT_T4_RTO,

    /**
     * {@code SCTP_EVENT_TIMEOUT_T5_SHUTDOWN_GUARD = 6}
     */
    @EnumMember(
        value = 6L,
        name = "SCTP_EVENT_TIMEOUT_T5_SHUTDOWN_GUARD"
    )
    SCTP_EVENT_TIMEOUT_T5_SHUTDOWN_GUARD,

    /**
     * {@code SCTP_EVENT_TIMEOUT_HEARTBEAT = 7}
     */
    @EnumMember(
        value = 7L,
        name = "SCTP_EVENT_TIMEOUT_HEARTBEAT"
    )
    SCTP_EVENT_TIMEOUT_HEARTBEAT,

    /**
     * {@code SCTP_EVENT_TIMEOUT_RECONF = 8}
     */
    @EnumMember(
        value = 8L,
        name = "SCTP_EVENT_TIMEOUT_RECONF"
    )
    SCTP_EVENT_TIMEOUT_RECONF,

    /**
     * {@code SCTP_EVENT_TIMEOUT_PROBE = 9}
     */
    @EnumMember(
        value = 9L,
        name = "SCTP_EVENT_TIMEOUT_PROBE"
    )
    SCTP_EVENT_TIMEOUT_PROBE,

    /**
     * {@code SCTP_EVENT_TIMEOUT_SACK = 10}
     */
    @EnumMember(
        value = 10L,
        name = "SCTP_EVENT_TIMEOUT_SACK"
    )
    SCTP_EVENT_TIMEOUT_SACK,

    /**
     * {@code SCTP_EVENT_TIMEOUT_AUTOCLOSE = 11}
     */
    @EnumMember(
        value = 11L,
        name = "SCTP_EVENT_TIMEOUT_AUTOCLOSE"
    )
    SCTP_EVENT_TIMEOUT_AUTOCLOSE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum sctp_state"
  )
  public enum sctp_state implements Enum<sctp_state>, TypedEnum<sctp_state, java.lang. @Unsigned Integer> {
    /**
     * {@code SCTP_STATE_CLOSED = 0}
     */
    @EnumMember(
        value = 0L,
        name = "SCTP_STATE_CLOSED"
    )
    SCTP_STATE_CLOSED,

    /**
     * {@code SCTP_STATE_COOKIE_WAIT = 1}
     */
    @EnumMember(
        value = 1L,
        name = "SCTP_STATE_COOKIE_WAIT"
    )
    SCTP_STATE_COOKIE_WAIT,

    /**
     * {@code SCTP_STATE_COOKIE_ECHOED = 2}
     */
    @EnumMember(
        value = 2L,
        name = "SCTP_STATE_COOKIE_ECHOED"
    )
    SCTP_STATE_COOKIE_ECHOED,

    /**
     * {@code SCTP_STATE_ESTABLISHED = 3}
     */
    @EnumMember(
        value = 3L,
        name = "SCTP_STATE_ESTABLISHED"
    )
    SCTP_STATE_ESTABLISHED,

    /**
     * {@code SCTP_STATE_SHUTDOWN_PENDING = 4}
     */
    @EnumMember(
        value = 4L,
        name = "SCTP_STATE_SHUTDOWN_PENDING"
    )
    SCTP_STATE_SHUTDOWN_PENDING,

    /**
     * {@code SCTP_STATE_SHUTDOWN_SENT = 5}
     */
    @EnumMember(
        value = 5L,
        name = "SCTP_STATE_SHUTDOWN_SENT"
    )
    SCTP_STATE_SHUTDOWN_SENT,

    /**
     * {@code SCTP_STATE_SHUTDOWN_RECEIVED = 6}
     */
    @EnumMember(
        value = 6L,
        name = "SCTP_STATE_SHUTDOWN_RECEIVED"
    )
    SCTP_STATE_SHUTDOWN_RECEIVED,

    /**
     * {@code SCTP_STATE_SHUTDOWN_ACK_SENT = 7}
     */
    @EnumMember(
        value = 7L,
        name = "SCTP_STATE_SHUTDOWN_ACK_SENT"
    )
    SCTP_STATE_SHUTDOWN_ACK_SENT
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum sctp_scope"
  )
  public enum sctp_scope implements Enum<sctp_scope>, TypedEnum<sctp_scope, java.lang. @Unsigned Integer> {
    /**
     * {@code SCTP_SCOPE_GLOBAL = 0}
     */
    @EnumMember(
        value = 0L,
        name = "SCTP_SCOPE_GLOBAL"
    )
    SCTP_SCOPE_GLOBAL,

    /**
     * {@code SCTP_SCOPE_PRIVATE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "SCTP_SCOPE_PRIVATE"
    )
    SCTP_SCOPE_PRIVATE,

    /**
     * {@code SCTP_SCOPE_LINK = 2}
     */
    @EnumMember(
        value = 2L,
        name = "SCTP_SCOPE_LINK"
    )
    SCTP_SCOPE_LINK,

    /**
     * {@code SCTP_SCOPE_LOOPBACK = 3}
     */
    @EnumMember(
        value = 3L,
        name = "SCTP_SCOPE_LOOPBACK"
    )
    SCTP_SCOPE_LOOPBACK,

    /**
     * {@code SCTP_SCOPE_UNUSABLE = 4}
     */
    @EnumMember(
        value = 4L,
        name = "SCTP_SCOPE_UNUSABLE"
    )
    SCTP_SCOPE_UNUSABLE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct sctp_tsnmap"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class sctp_tsnmap extends Struct {
    public Ptr<java.lang. @Unsigned Long> tsn_map;

    public @Unsigned int base_tsn;

    public @Unsigned int cumulative_tsn_ack_point;

    public @Unsigned int max_tsn_seen;

    public @Unsigned short len;

    public @Unsigned short pending_data;

    public @Unsigned short num_dup_tsns;

    public @Unsigned @OriginalName("__be32") int @Size(16) [] dup_tsns;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct sctp_ulpevent"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class sctp_ulpevent extends Struct {
    public Ptr<sctp_association> asoc;

    public Ptr<sctp_chunk> chunk;

    public @Unsigned int rmem_len;

    @InlineUnion(27792)
    public @Unsigned int mid;

    @InlineUnion(27792)
    public @Unsigned short ssn;

    @InlineUnion(27793)
    public @Unsigned int ppid;

    @InlineUnion(27793)
    public @Unsigned int fsn;

    public @Unsigned int tsn;

    public @Unsigned int cumtsn;

    public @Unsigned short stream;

    public @Unsigned short flags;

    public @Unsigned short msg_flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct sctp_chunk"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class sctp_chunk extends Struct {
    public list_head list;

    public @OriginalName("refcount_t") refcount_struct refcnt;

    public int sent_count;

    @InlineUnion(27913)
    public list_head transmitted_list;

    @InlineUnion(27913)
    public list_head stream_list;

    public list_head frag_list;

    public Ptr<sk_buff> skb;

    @InlineUnion(27914)
    public Ptr<sk_buff> head_skb;

    @InlineUnion(27914)
    public Ptr<sctp_shared_key> shkey;

    public sctp_params param_hdr;

    public subh_of_sctp_chunk subh;

    public Ptr<java.lang.Character> chunk_end;

    public Ptr<sctp_chunkhdr> chunk_hdr;

    public Ptr<sctphdr> sctp_hdr;

    public sctp_sndrcvinfo sinfo;

    public Ptr<sctp_association> asoc;

    public Ptr<sctp_ep_common> rcvr;

    public @Unsigned long sent_at;

    public sctp_addr source;

    public sctp_addr dest;

    public Ptr<sctp_datamsg> msg;

    public Ptr<sctp_transport> transport;

    public Ptr<sk_buff> auth_chunk;

    public @Unsigned short rtt_in_progress;

    public @Unsigned short has_tsn;

    public @Unsigned short has_ssn;

    public @Unsigned short singleton;

    public @Unsigned short end_of_packet;

    public @Unsigned short ecn_ce_done;

    public @Unsigned short pdiscard;

    public @Unsigned short tsn_gap_acked;

    public @Unsigned short data_accepted;

    public @Unsigned short auth;

    public @Unsigned short has_asconf;

    public @Unsigned short pmtu_probe;

    public @Unsigned short tsn_missing_report;

    public @Unsigned short fast_retransmit;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct sctp_ulpq"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class sctp_ulpq extends Struct {
    public char pd_mode;

    public Ptr<sctp_association> asoc;

    public sk_buff_head reasm;

    public sk_buff_head reasm_uo;

    public sk_buff_head lobby;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct sctp_stream_interleave"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class sctp_stream_interleave extends Struct {
    public @Unsigned short data_chunk_len;

    public @Unsigned short ftsn_chunk_len;

    public Ptr<?> make_datafrag;

    public Ptr<?> assign_number;

    public Ptr<?> validate_data;

    public Ptr<?> ulpevent_data;

    public Ptr<?> enqueue_event;

    public Ptr<?> renege_events;

    public Ptr<?> start_pd;

    public Ptr<?> abort_pd;

    public Ptr<?> generate_ftsn;

    public Ptr<?> validate_ftsn;

    public Ptr<?> report_ftsn;

    public Ptr<?> handle_ftsn;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct sctp_outq"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class sctp_outq extends Struct {
    public Ptr<sctp_association> asoc;

    public list_head out_chunk_list;

    public @OriginalName("sctp_sched_ops") Ptr<?> sched;

    public @Unsigned int out_qlen;

    public @Unsigned int error;

    public list_head control_chunk_list;

    public list_head sacked;

    public list_head retransmit;

    public list_head abandoned;

    public @Unsigned int outstanding_bytes;

    public char fast_rtx;

    public char cork;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct sctp_bind_bucket"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class sctp_bind_bucket extends Struct {
    public @Unsigned short port;

    public byte fastreuse;

    public byte fastreuseport;

    public kuid_t fastuid;

    public hlist_node node;

    public hlist_head owner;

    public Ptr<net> net;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum sctp_socket_type"
  )
  public enum sctp_socket_type implements Enum<sctp_socket_type>, TypedEnum<sctp_socket_type, java.lang. @Unsigned Integer> {
    /**
     * {@code SCTP_SOCKET_UDP = 0}
     */
    @EnumMember(
        value = 0L,
        name = "SCTP_SOCKET_UDP"
    )
    SCTP_SOCKET_UDP,

    /**
     * {@code SCTP_SOCKET_UDP_HIGH_BANDWIDTH = 1}
     */
    @EnumMember(
        value = 1L,
        name = "SCTP_SOCKET_UDP_HIGH_BANDWIDTH"
    )
    SCTP_SOCKET_UDP_HIGH_BANDWIDTH,

    /**
     * {@code SCTP_SOCKET_TCP = 2}
     */
    @EnumMember(
        value = 2L,
        name = "SCTP_SOCKET_TCP"
    )
    SCTP_SOCKET_TCP
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct sctp_sock"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class sctp_sock extends Struct {
    public inet_sock inet;

    public sctp_socket_type type;

    public Ptr<sctp_pf> pf;

    public Ptr<crypto_shash> hmac;

    public String sctp_hmac_alg;

    public Ptr<sctp_endpoint> ep;

    public Ptr<sctp_bind_bucket> bind_hash;

    public @Unsigned short default_stream;

    public @Unsigned int default_ppid;

    public @Unsigned short default_flags;

    public @Unsigned int default_context;

    public @Unsigned int default_timetolive;

    public @Unsigned int default_rcv_context;

    public int max_burst;

    public @Unsigned int hbinterval;

    public @Unsigned int probe_interval;

    public @Unsigned @OriginalName("__be16") short udp_port;

    public @Unsigned @OriginalName("__be16") short encap_port;

    public @Unsigned short pathmaxrxt;

    public @Unsigned int flowlabel;

    public char dscp;

    public @Unsigned short pf_retrans;

    public @Unsigned short ps_retrans;

    public @Unsigned int pathmtu;

    public @Unsigned int sackdelay;

    public @Unsigned int sackfreq;

    public @Unsigned int param_flags;

    public @Unsigned int default_ss;

    public sctp_rtoinfo rtoinfo;

    public sctp_paddrparams paddrparam;

    public sctp_assocparams assocparams;

    public @Unsigned short subscribe;

    public sctp_initmsg initmsg;

    public int user_frag;

    public @Unsigned int autoclose;

    public @Unsigned int adaptation_ind;

    public @Unsigned int pd_point;

    public @Unsigned short nodelay;

    public @Unsigned short pf_expose;

    public @Unsigned short reuse;

    public @Unsigned short disable_fragments;

    public @Unsigned short v4mapped;

    public @Unsigned short frag_interleave;

    public @Unsigned short recvrcvinfo;

    public @Unsigned short recvnxtinfo;

    public @Unsigned short data_ready_signalled;

    public atomic_t pd_mode;

    public sk_buff_head pd_lobby;

    public list_head auto_asconf_list;

    public int do_auto_asconf;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct sctp_pf"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class sctp_pf extends Struct {
    public Ptr<?> event_msgname;

    public Ptr<?> skb_msgname;

    public Ptr<?> af_supported;

    public Ptr<?> cmp_addr;

    public Ptr<?> bind_verify;

    public Ptr<?> send_verify;

    public Ptr<?> supported_addrs;

    public Ptr<?> create_accept_sk;

    public Ptr<?> addr_to_user;

    public Ptr<?> to_sk_saddr;

    public Ptr<?> to_sk_daddr;

    public Ptr<?> copy_ip_options;

    public Ptr<sctp_af> af;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct sctp_endpoint"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class sctp_endpoint extends Struct {
    public sctp_ep_common base;

    public hlist_node node;

    public int hashent;

    public list_head asocs;

    public char @Size(32) [] secret_key;

    public Ptr<java.lang.Character> digest;

    public @Unsigned int sndbuf_policy;

    public @Unsigned int rcvbuf_policy;

    public Ptr<Ptr<crypto_shash>> auth_hmacs;

    public Ptr<sctp_hmac_algo_param> auth_hmacs_list;

    public Ptr<sctp_chunks_param> auth_chunk_list;

    public list_head endpoint_shared_keys;

    public @Unsigned short active_key_id;

    public char ecn_enable;

    public char auth_enable;

    public char intl_enable;

    public char prsctp_enable;

    public char asconf_enable;

    public char reconf_enable;

    public char strreset_enable;

    public callback_head rcu;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct sctp_cookie"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class sctp_cookie extends Struct {
    public @Unsigned int my_vtag;

    public @Unsigned int peer_vtag;

    public @Unsigned int my_ttag;

    public @Unsigned int peer_ttag;

    public @OriginalName("ktime_t") long expiration;

    public @Unsigned short sinit_num_ostreams;

    public @Unsigned short sinit_max_instreams;

    public @Unsigned int initial_tsn;

    public sctp_addr peer_addr;

    public @Unsigned short my_port;

    public char prsctp_capable;

    public char padding;

    public @Unsigned int adaptation_ind;

    public char @Size(36) [] auth_random;

    public char @Size(10) [] auth_hmacs;

    public char @Size(20) [] auth_chunks;

    public @Unsigned int raw_addr_list_len;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct sctp_signed_cookie"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class sctp_signed_cookie extends Struct {
    public char @Size(32) [] signature;

    public @Unsigned int __pad;

    public sctp_cookie c;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union sctp_addr_param"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class sctp_addr_param extends Union {
    public sctp_paramhdr p;

    public sctp_ipv4addr_param v4;

    public sctp_ipv6addr_param v6;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union sctp_params"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class sctp_params extends Union {
    public Ptr<?> v;

    public Ptr<sctp_paramhdr> p;

    public Ptr<sctp_cookie_preserve_param> life;

    public Ptr<sctp_hostname_param> dns;

    public Ptr<sctp_cookie_param> cookie;

    public Ptr<sctp_supported_addrs_param> sat;

    public Ptr<sctp_ipv4addr_param> v4;

    public Ptr<sctp_ipv6addr_param> v6;

    public Ptr<sctp_addr_param> addr;

    public Ptr<sctp_adaptation_ind_param> aind;

    public Ptr<sctp_supported_ext_param> ext;

    public Ptr<sctp_random_param> random;

    public Ptr<sctp_chunks_param> chunks;

    public Ptr<sctp_hmac_algo_param> hmac_algo;

    public Ptr<sctp_addip_param> addip;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct sctp_sender_hb_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class sctp_sender_hb_info extends Struct {
    public sctp_paramhdr param_hdr;

    public sctp_addr daddr;

    public @Unsigned long sent_at;

    public @Unsigned long hb_nonce;

    public @Unsigned int probe_size;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct sctp_af"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class sctp_af extends Struct {
    public Ptr<?> sctp_xmit;

    public Ptr<?> setsockopt;

    public Ptr<?> getsockopt;

    public Ptr<?> get_dst;

    public Ptr<?> get_saddr;

    public Ptr<?> copy_addrlist;

    public Ptr<?> cmp_addr;

    public Ptr<?> addr_copy;

    public Ptr<?> from_skb;

    public Ptr<?> from_sk;

    public Ptr<?> from_addr_param;

    public Ptr<?> to_addr_param;

    public Ptr<?> addr_valid;

    public Ptr<?> scope;

    public Ptr<?> inaddr_any;

    public Ptr<?> is_any;

    public Ptr<?> available;

    public Ptr<?> skb_iif;

    public Ptr<?> skb_sdif;

    public Ptr<?> is_ce;

    public Ptr<?> seq_dump_addr;

    public Ptr<?> ecn_capable;

    public @Unsigned short net_header_len;

    public int sockaddr_len;

    public Ptr<?> ip_options_len;

    public @Unsigned @OriginalName("sa_family_t") short sa_family;

    public list_head list;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct sctp_transport"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class sctp_transport extends Struct {
    public list_head transports;

    public rhlist_head node;

    public @OriginalName("refcount_t") refcount_struct refcnt;

    public @Unsigned int dead;

    public @Unsigned int rto_pending;

    public @Unsigned int hb_sent;

    public @Unsigned int pmtu_pending;

    public @Unsigned int dst_pending_confirm;

    public @Unsigned int sack_generation;

    public @Unsigned int dst_cookie;

    public flowi fl;

    public sctp_addr ipaddr;

    public Ptr<sctp_af> af_specific;

    public Ptr<sctp_association> asoc;

    public @Unsigned long rto;

    public @Unsigned int rtt;

    public @Unsigned int rttvar;

    public @Unsigned int srtt;

    public @Unsigned int cwnd;

    public @Unsigned int ssthresh;

    public @Unsigned int partial_bytes_acked;

    public @Unsigned int flight_size;

    public @Unsigned int burst_limited;

    public Ptr<dst_entry> dst;

    public sctp_addr saddr;

    public @Unsigned long hbinterval;

    public @Unsigned long probe_interval;

    public @Unsigned long sackdelay;

    public @Unsigned int sackfreq;

    public atomic_t mtu_info;

    public @OriginalName("ktime_t") long last_time_heard;

    public @Unsigned long last_time_sent;

    public @Unsigned long last_time_ecne_reduced;

    public @Unsigned @OriginalName("__be16") short encap_port;

    public @Unsigned short pathmaxrxt;

    public @Unsigned int flowlabel;

    public char dscp;

    public @Unsigned short pf_retrans;

    public @Unsigned short ps_retrans;

    public @Unsigned int pathmtu;

    public @Unsigned int param_flags;

    public int init_sent_count;

    public int state;

    public @Unsigned short error_count;

    public timer_list T3_rtx_timer;

    public timer_list hb_timer;

    public timer_list proto_unreach_timer;

    public timer_list reconf_timer;

    public timer_list probe_timer;

    public list_head transmitted;

    public sctp_packet packet;

    public list_head send_ready;

    public cacc_of_sctp_transport cacc;

    public pl_of_sctp_transport pl;

    public @Unsigned long hb_nonce;

    public callback_head rcu;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct sctp_datamsg"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class sctp_datamsg extends Struct {
    public list_head chunks;

    public @OriginalName("refcount_t") refcount_struct refcnt;

    public @Unsigned long expires_at;

    public int send_error;

    public char send_failed;

    public char can_delay;

    public char abandoned;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct sctp_ep_common"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class sctp_ep_common extends Struct {
    public sctp_endpoint_type type;

    public @OriginalName("refcount_t") refcount_struct refcnt;

    public boolean dead;

    public Ptr<sock> sk;

    public Ptr<net> net;

    public sctp_inq inqueue;

    public sctp_bind_addr bind_addr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct sctp_packet"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class sctp_packet extends Struct {
    public @Unsigned short source_port;

    public @Unsigned short destination_port;

    public @Unsigned int vtag;

    public list_head chunk_list;

    public @Unsigned long overhead;

    public @Unsigned long size;

    public @Unsigned long max_size;

    public Ptr<sctp_transport> transport;

    public Ptr<sctp_chunk> auth;

    public char has_cookie_echo;

    public char has_sack;

    public char has_auth;

    public char has_data;

    public char ipfragok;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct sctp_inq"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class sctp_inq extends Struct {
    public list_head in_chunk_list;

    public Ptr<sctp_chunk> in_progress;

    public work_struct immediate;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct sctp_bind_addr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class sctp_bind_addr extends Struct {
    public @Unsigned short port;

    public list_head address_list;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum sctp_endpoint_type"
  )
  public enum sctp_endpoint_type implements Enum<sctp_endpoint_type>, TypedEnum<sctp_endpoint_type, java.lang. @Unsigned Integer> {
    /**
     * {@code SCTP_EP_TYPE_SOCKET = 0}
     */
    @EnumMember(
        value = 0L,
        name = "SCTP_EP_TYPE_SOCKET"
    )
    SCTP_EP_TYPE_SOCKET,

    /**
     * {@code SCTP_EP_TYPE_ASSOCIATION = 1}
     */
    @EnumMember(
        value = 1L,
        name = "SCTP_EP_TYPE_ASSOCIATION"
    )
    SCTP_EP_TYPE_ASSOCIATION
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct sctp_inithdr_host"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class sctp_inithdr_host extends Struct {
    public @Unsigned int init_tag;

    public @Unsigned int a_rwnd;

    public @Unsigned short num_outbound_streams;

    public @Unsigned short num_inbound_streams;

    public @Unsigned int initial_tsn;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct sctp_stream_priorities"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class sctp_stream_priorities extends Struct {
    public list_head prio_sched;

    public list_head active;

    public Ptr<sctp_stream_out_ext> next;

    public @Unsigned short prio;

    public @Unsigned short users;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct sctp_stream_out_ext"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class sctp_stream_out_ext extends Struct {
    public @Unsigned long @Size(3) [] abandoned_unsent;

    public @Unsigned long @Size(3) [] abandoned_sent;

    public list_head outq;

    @InlineUnion(27953)
    public anon_member_of_anon_member_of_sctp_stream_out_ext anon3$0;

    @InlineUnion(27953)
    public anon_member_of_anon_member_of_sctp_stream_out_ext anon3$1;

    @InlineUnion(27953)
    public anon_member_of_anon_member_of_sctp_stream_out_ext anon3$2;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct sctp_stream_out"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class sctp_stream_out extends Struct {
    @InlineUnion(27792)
    public @Unsigned int mid;

    @InlineUnion(27792)
    public @Unsigned short ssn;

    public @Unsigned int mid_uo;

    public Ptr<sctp_stream_out_ext> ext;

    public char state;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct sctp_stream_in"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class sctp_stream_in extends Struct {
    @InlineUnion(27792)
    public @Unsigned int mid;

    @InlineUnion(27792)
    public @Unsigned short ssn;

    public @Unsigned int mid_uo;

    public @Unsigned int fsn;

    public @Unsigned int fsn_uo;

    public char pd_mode;

    public char pd_mode_uo;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct sctp_stream"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class sctp_stream extends Struct {
    public out_of_sctp_stream out;

    public in_of_sctp_stream in;

    public @Unsigned short outcnt;

    public @Unsigned short incnt;

    public Ptr<sctp_stream_out> out_curr;

    @InlineUnion(27963)
    public anon_member_of_anon_member_of_sctp_stream anon5$0;

    @InlineUnion(27963)
    public anon_member_of_anon_member_of_sctp_stream anon5$1;

    @InlineUnion(27963)
    public anon_member_of_anon_member_of_sctp_stream anon5$2;

    public Ptr<sctp_stream_interleave> si;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct sctp_priv_assoc_stats"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class sctp_priv_assoc_stats extends Struct {
    public __kernel_sockaddr_storage obs_rto_ipaddr;

    public @Unsigned long max_obs_rto;

    public @Unsigned long isacks;

    public @Unsigned long osacks;

    public @Unsigned long opackets;

    public @Unsigned long ipackets;

    public @Unsigned long rtxchunks;

    public @Unsigned long outofseqtsns;

    public @Unsigned long idupchunks;

    public @Unsigned long gapcnt;

    public @Unsigned long ouodchunks;

    public @Unsigned long iuodchunks;

    public @Unsigned long oodchunks;

    public @Unsigned long iodchunks;

    public @Unsigned long octrlchunks;

    public @Unsigned long ictrlchunks;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum sctp_assoc_state_of_sk_security_struct"
  )
  public enum sctp_assoc_state_of_sk_security_struct implements Enum<sctp_assoc_state_of_sk_security_struct>, TypedEnum<sctp_assoc_state_of_sk_security_struct, java.lang. @Unsigned Integer> {
    /**
     * {@code SCTP_ASSOC_UNSET = 0}
     */
    @EnumMember(
        value = 0L,
        name = "SCTP_ASSOC_UNSET"
    )
    SCTP_ASSOC_UNSET,

    /**
     * {@code SCTP_ASSOC_SET = 1}
     */
    @EnumMember(
        value = 1L,
        name = "SCTP_ASSOC_SET"
    )
    SCTP_ASSOC_SET
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct sctphdr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class sctphdr extends Struct {
    public @Unsigned @OriginalName("__be16") short source;

    public @Unsigned @OriginalName("__be16") short dest;

    public @Unsigned @OriginalName("__be32") int vtag;

    public @Unsigned @OriginalName("__le32") int checksum;
  }
}
